// ── Recipe Cache (in-memory, per serverless instance) ───────────
const recipeCache = new Map();
const CACHE_TTL_MS = 60 * 60 * 1000; // 1 hour
const CACHE_MAX_ENTRIES = 200;

function getCached(url) {
  const entry = recipeCache.get(url);
  if (!entry) return null;
  if (Date.now() - entry.timestamp > CACHE_TTL_MS) {
    recipeCache.delete(url);
    return null;
  }
  return entry.data;
}

function setCache(url, data) {
  if (recipeCache.size >= CACHE_MAX_ENTRIES) {
    const oldest = recipeCache.keys().next().value;
    recipeCache.delete(oldest);
  }
  recipeCache.set(url, { data, timestamp: Date.now() });
}

// ── Rate Limiting (in-memory, per serverless instance) ──────────
const rateLimitMap = new Map();
const RATE_LIMIT_WINDOW_MS = 60 * 1000; // 1 minute
const RATE_LIMIT_MAX = 10; // 10 requests per window

function checkRateLimit(ip) {
  const now = Date.now();
  const entry = rateLimitMap.get(ip);

  if (!entry) {
    rateLimitMap.set(ip, { timestamps: [now] });
    return true;
  }

  entry.timestamps = entry.timestamps.filter(t => now - t < RATE_LIMIT_WINDOW_MS);

  if (entry.timestamps.length >= RATE_LIMIT_MAX) {
    return false;
  }

  entry.timestamps.push(now);
  return true;
}

// Clean up stale entries every 5 minutes
setInterval(() => {
  const now = Date.now();
  for (const [ip, entry] of rateLimitMap) {
    entry.timestamps = entry.timestamps.filter(t => now - t < RATE_LIMIT_WINDOW_MS);
    if (entry.timestamps.length === 0) rateLimitMap.delete(ip);
  }
}, 5 * 60 * 1000);

// ── Domain Allowlist ────────────────────────────────────────────
const ALLOWED_DOMAINS = new Set([
  'recipetineats.com',
  'budgetbytes.com',
  'allrecipes.com',
  'foodnetwork.com',
  'simplyrecipes.com',
  'bonappetit.com',
  'seriouseats.com',
  'tasty.co',
  'delish.com',
  'epicurious.com',
  'cookieandkate.com',
  'minimalistbaker.com',
  'halfbakedharvest.com',
  'damndelicious.net',
  'pinchofyum.com',
  'smittenkitchen.com',
  'loveandlemons.com',
  'thepioneerwoman.com',
  'food52.com',
  'eatingwell.com',
  'skinnytaste.com',
  'hellofresh.com',
  'bbcgoodfood.com',
  'jamieoliver.com',
  'nigella.com',
  'themodernproper.com',
]);

function isDomainAllowed(urlString) {
  let parsed;
  try {
    parsed = new URL(urlString);
  } catch {
    return false;
  }
  const hostname = parsed.hostname.toLowerCase().replace(/^www\./, '');
  return ALLOWED_DOMAINS.has(hostname);
}

// ── SSRF Protection ─────────────────────────────────────────────
function isUrlSafe(urlString) {
  let parsed;
  try {
    parsed = new URL(urlString);
  } catch {
    return false;
  }

  // Only allow https
  if (parsed.protocol !== 'https:') {
    return false;
  }

  // Block credentials in URL
  if (parsed.username || parsed.password) {
    return false;
  }

  const hostname = parsed.hostname.toLowerCase();

  // Block localhost variants
  if (hostname === 'localhost' || hostname === '0.0.0.0' || hostname === '[::1]') {
    return false;
  }

  // Block internal/private IP ranges
  const ipv4Match = hostname.match(/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/);
  if (ipv4Match) {
    const [, a, b] = ipv4Match.map(Number);
    if (a === 127) return false;
    if (a === 10) return false;
    if (a === 172 && b >= 16 && b <= 31) return false;
    if (a === 192 && b === 168) return false;
    if (a === 169 && b === 254) return false;
    if (a === 0) return false;
  }

  // Block cloud metadata endpoints
  if (hostname === 'metadata.google.internal' || hostname === 'metadata.google.com') {
    return false;
  }

  return true;
}

// ── HTML Sanitization ───────────────────────────────────────────
function sanitizeText(str) {
  if (typeof str !== 'string') return str;

  return str
    .replace(/<\s*\/?\s*(script|iframe|object|embed|form|link|style|base|meta|svg)\b[^>]*>/gi, '')
    .replace(/\s+on\w+\s*=\s*(?:"[^"]*"|'[^']*'|[^\s>]*)/gi, '')
    .replace(/(href|src|action)\s*=\s*["']?\s*(javascript|data|vbscript)\s*:/gi, '$1="')
    .replace(/<script\b[^>]*>[\s\S]*?<\/script>/gi, '');
}

function sanitizeRecipe(recipe) {
  if (recipe.name) recipe.name = sanitizeText(recipe.name);
  if (recipe.description) recipe.description = sanitizeText(recipe.description);
  if (Array.isArray(recipe.instructions)) {
    recipe.instructions = recipe.instructions.map(s => sanitizeText(s));
  }
  if (Array.isArray(recipe.ingredients)) {
    recipe.ingredients = recipe.ingredients.map(s => sanitizeText(s));
  }
  return recipe;
}

// ── Main Handler ────────────────────────────────────────────────
export default async function handler(req, res) {
  // CORS headers
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');

  if (req.method === 'OPTIONS') {
    return res.status(200).end();
  }

  if (req.method !== 'POST') {
    return res.status(405).json({ error: 'Method not allowed' });
  }

  // Rate limiting
  const clientIp = req.headers['x-forwarded-for']?.split(',')[0]?.trim()
    || req.headers['x-real-ip']
    || req.socket?.remoteAddress
    || 'unknown';

  if (!checkRateLimit(clientIp)) {
    return res.status(429).json({
      error: 'Too many requests. Please wait a minute before trying again.',
    });
  }

  const { url } = req.body;

  if (!url) {
    return res.status(400).json({ error: 'URL is required' });
  }

  // URL validation (SSRF protection)
  if (!isUrlSafe(url)) {
    return res.status(400).json({ error: 'Invalid URL. Please use an https:// link.' });
  }

  // Domain allowlist
  if (!isDomainAllowed(url)) {
    return res.status(400).json({ error: 'This recipe site is not supported yet. Try a major recipe site like RecipeTin Eats, BBC Good Food, or Allrecipes.' });
  }

  // Check cache first
  const cached = getCached(url);
  if (cached) {
    res.setHeader('X-Cache', 'HIT');
    return res.status(200).json(cached);
  }

  try {
    const response = await fetch(url, {
      headers: {
        'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
        'Accept-Language': 'en-US,en;q=0.9',
      },
      redirect: 'follow',
      signal: AbortSignal.timeout(10000), // 10s timeout
    });

    if (!response.ok) {
      return res.status(502).json({ error: 'Could not fetch recipe page' });
    }

    const html = await response.text();

    // Limit response size (2MB max)
    if (html.length > 2 * 1024 * 1024) {
      return res.status(502).json({ error: 'Page too large to process' });
    }

    // Extract JSON-LD blocks
    const jsonLdRegex = /<script[^>]*type=["']application\/ld\+json["'][^>]*>([\s\S]*?)<\/script>/gi;
    const matches = [];
    let match;
    while ((match = jsonLdRegex.exec(html)) !== null) {
      try {
        matches.push(JSON.parse(match[1]));
      } catch (e) {
        // skip malformed JSON-LD
      }
    }

    // Find Recipe object
    let recipe = null;
    for (const data of matches) {
      if (data['@type'] === 'Recipe') {
        recipe = data;
        break;
      }
      if (Array.isArray(data)) {
        recipe = data.find(item => item['@type'] === 'Recipe');
        if (recipe) break;
      }
      if (data['@graph'] && Array.isArray(data['@graph'])) {
        recipe = data['@graph'].find(item => item['@type'] === 'Recipe');
        if (recipe) break;
      }
    }

    if (!recipe) {
      return res.status(404).json({ error: 'No recipe found on this page' });
    }

    // Extract fields
    const result = {
      name: recipe.name || 'Untitled Recipe',
      description: recipe.description || '',
      ingredients: (recipe.recipeIngredient || []).map(i =>
        typeof i === 'string' ? i.trim() : ''
      ),
      instructions: [],
      servings: recipe.recipeYield || null,
      prepTime: recipe.prepTime || null,
      cookTime: recipe.cookTime || null,
      image: null,
    };

    // Parse instructions
    if (recipe.recipeInstructions) {
      if (Array.isArray(recipe.recipeInstructions)) {
        result.instructions = recipe.recipeInstructions.map(step => {
          if (typeof step === 'string') return step;
          if (step.text) return step.text;
          if (step.name) return step.name;
          return '';
        }).filter(Boolean);
      } else if (typeof recipe.recipeInstructions === 'string') {
        result.instructions = [recipe.recipeInstructions];
      }
    }

    // Get image
    if (recipe.image) {
      if (typeof recipe.image === 'string') result.image = recipe.image;
      else if (Array.isArray(recipe.image)) result.image = recipe.image[0];
      else if (recipe.image.url) result.image = recipe.image.url;
    }

    // Validate image URL
    if (result.image && typeof result.image === 'string') {
      try {
        const imgUrl = new URL(result.image);
        if (imgUrl.protocol !== 'http:' && imgUrl.protocol !== 'https:') {
          result.image = null;
        }
      } catch {
        result.image = null;
      }
    }

    // Sanitize all text content
    sanitizeRecipe(result);

    // Cache the result
    setCache(url, result);
    res.setHeader('X-Cache', 'MISS');

    return res.status(200).json(result);
  } catch (error) {
    if (error.name === 'TimeoutError' || error.name === 'AbortError') {
      return res.status(504).json({ error: 'Recipe page took too long to respond' });
    }
    return res.status(500).json({ error: 'Failed to process recipe' });
  }
}
