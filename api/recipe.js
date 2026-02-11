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

  const { url } = req.body;

  if (!url) {
    return res.status(400).json({ error: 'URL is required' });
  }

  try {
    const response = await fetch(url, {
      headers: {
        'User-Agent': 'Mozilla/5.0 (compatible; Miiro/1.0; +https://getmiiro.app)',
        'Accept': 'text/html,application/xhtml+xml',
      },
    });

    if (!response.ok) {
      return res.status(502).json({ error: 'Could not fetch recipe page' });
    }

    const html = await response.text();

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
      ingredients: (recipe.recipeIngredient || []).map(i => i.trim()),
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

    return res.status(200).json(result);
  } catch (error) {
    return res.status(500).json({ error: 'Failed to process recipe: ' + error.message });
  }
}

