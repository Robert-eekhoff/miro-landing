# Miiro SEO Action Plan

**Date:** 2026-05-14
**Companion to:** `FULL-AUDIT-REPORT.md`
**Overall score:** 84/100. No critical regressions. The deploy is solid.

This file lists prioritized fixes. Each item has: estimated impact, estimated effort, confidence, and the exact change to make.

---

## 🔴 Critical (do today)

**(none)** — no findings rise to critical. Skip to High.

---

## ⚠️ High Priority (do this week)

### H1 — Add in-HTML hreflang to blog posts that have an EN↔NL pair
**Impact:** Faster + more reliable EN↔NL pairing in Google, Bing, Yandex. Currently declared only in sitemap.
**Effort:** Medium (touches every paired post — ~14 EN + ~10 NL). Templating-friendly.
**Confidence:** Confirmed

For each paired post, add to `<head>`:

```html
<link rel="alternate" hreflang="en" href="https://miiro.app/blog/{en-slug}">
<link rel="alternate" hreflang="nl" href="https://miiro.app/nl/blog/{nl-slug}">
<link rel="alternate" hreflang="x-default" href="https://miiro.app/blog/{en-slug}">
```

**Verify the mapping matches `sitemap.xml`** — sitemap already has the authoritative pairs.

For **NL-only** posts (`klender-vs-miiro`, `klender-alternatieven`, `timetree-alternatief`, `weekmenu-maken-tips`, `google-agenda-delen-partner`, `apps-samenwonen`, `app-tips-druk-gezinsleven`) — **do not add hreflang**. Self-referencing canonical is sufficient.

---

### H2 — Bring EN homepage schema to parity with NL
**Impact:** EN GEO + Google's entity graph. NL is meaningfully richer right now.
**Effort:** Small (1 file, copy patterns from NL)
**Confidence:** Confirmed

Add to EN `<script type="application/ld+json">` `@graph`:

1. **`WebPage`** node with `inLanguage: "en"`, `isPartOf: WebSite`.
2. **`FAQPage`** node with 6–8 English-localized Q&As (parallel to NL: "What is Tell Miiro?", "How is Miiro free?", "Does my partner pay?", "Where does Miiro order groceries?" → list US/EN-relevant stores: Instacart, Whole Foods, Walmart, Kroger, **or omit if grocery integration is NL-only and clarify that in the FAQ**, "Is my data secure?", "How is Miiro different from Google Calendar?", "Can I save recipes from TikTok/Instagram?").
3. **`foundingLocation`** on Organization — if the company is Amsterdam-based, include it on EN too (it's the same legal entity).
4. **`inLanguage: ["en","nl"]`** on the SoftwareApplication node.

> **Decision point — FAQPage:** Google restricts FAQ rich results to gov/health since Aug 2023. FAQPage on commercial sites still helps **AI search engines** (Perplexity, ChatGPT, Claude search) extract answers. Keep on both locales for GEO value.

---

### H3 — Add Content-Security-Policy header
**Impact:** Best Practices Lighthouse score, XSS resilience, GEO trust signal.
**Effort:** Medium — there are inline `<style>` and inline `<script>` blocks, so CSP needs careful `'unsafe-inline'` or hash carve-outs.
**Confidence:** Confirmed

Add to `vercel.json` (or `vercel.ts`) `headers`:

```json
{
  "source": "/(.*)",
  "headers": [
    {
      "key": "Content-Security-Policy",
      "value": "default-src 'self'; script-src 'self' 'unsafe-inline' https://www.googletagmanager.com https://www.google-analytics.com; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src 'self' https://fonts.gstatic.com; img-src 'self' data: https:; connect-src 'self' https://www.google-analytics.com; frame-ancestors 'none'; base-uri 'self'; form-action 'self'"
    }
  ]
}
```

**Test in `Content-Security-Policy-Report-Only` mode first** before enforcing — set the header above with `-Report-Only` suffix, ship to prod, watch console for 24h, then switch.

---

### H4 — Add `/llms.txt`
**Impact:** Big GEO win. Anthropic, Mistral, and others increasingly look here. Easiest GEO improvement in the audit.
**Effort:** Trivial (1 markdown file)
**Confidence:** Confirmed

Create `/llms.txt` at the site root:

```
# Miiro — Household app for couples and families

> Miiro is a household management app for couples and families. Tell Sam (the AI) what your household needs in plain language, and it organizes tasks, calendars, meals, recipes, and grocery orders. iOS first.

## What Miiro does
- Plain-language input via Tell Miiro AI → auto-sorted into tasks, events, meals, grocery lists
- Shared grocery lists with supermarket integration (Albert Heijn, Jumbo, Picnic, Crisp, Plus — NL)
- Recipe import from TikTok, Instagram, YouTube, recipe sites
- Meal planning and shared cookbook
- Shared calendar for couples
- One subscription covers a household of up to 6

## Pricing
- 7-day free trial of Miiro+
- $9.99/month or $59.99/year (US)
- €9,99/maand of €59,99/jaar (NL)

## Key pages
- [Homepage (EN)](https://miiro.app/)
- [Homepage (NL)](https://miiro.app/nl/)
- [Blog (EN)](https://miiro.app/blog/)
- [Blog (NL)](https://miiro.app/nl/blog/)
- [App Store](https://apps.apple.com/app/miiro-couple-family-planner/id6759159052)

## Optional
- [Privacy](https://miiro.app/privacy)
- [Support](https://miiro.app/support)
- [Terms](https://miiro.app/terms)
```

Also serve at `/llms-full.txt` if you want a longer machine-readable version (optional — the short file is enough to start).

---

### H5 — Fix EN `og:url` to match canonical
**Impact:** Tiny SEO impact, but prevents off-by-one inconsistency surfacing in Facebook/Twitter crawls and Search Console.
**Effort:** Trivial
**Confidence:** Confirmed

In EN `<head>`:

```diff
- <meta property="og:url" content="https://miiro.app">
+ <meta property="og:url" content="https://miiro.app/">
```

While there, add `<meta property="og:site_name" content="Miiro">` (M1 below — same file).

---

## 🟡 Medium Priority (do this month)

### M1 — Add `og:site_name` to EN homepage
**Impact:** Small. Search engines and social previews use it for source attribution.
**Effort:** Trivial
**Confidence:** Confirmed

```diff
+ <meta property="og:site_name" content="Miiro">
```

Add to EN `<head>` after `og:type`.

---

### M2 — Tighten HSTS
**Impact:** Security score + eligibility for HSTS preload list.
**Effort:** Trivial
**Confidence:** Confirmed

In Vercel config:

```diff
- Strict-Transport-Security: max-age=63072000
+ Strict-Transport-Security: max-age=63072000; includeSubDomains; preload
```

After 1 week stable, submit `miiro.app` to https://hstspreload.org/.

---

### M3 — Add Blog/CollectionPage schema to `/nl/blog/` index
**Impact:** Helps Google understand the page as a blog hub; useful for Discover.
**Effort:** Small
**Confidence:** Confirmed

```html
<script type="application/ld+json">
{
  "@context": "https://schema.org",
  "@type": "CollectionPage",
  "name": "Miiro Blog — Tips voor Koppels en Huishouden",
  "url": "https://miiro.app/nl/blog/",
  "inLanguage": "nl",
  "isPartOf": { "@type": "WebSite", "name": "Miiro", "url": "https://miiro.app" },
  "about": [
    { "@type": "Thing", "name": "Household management" },
    { "@type": "Thing", "name": "Couples productivity" },
    { "@type": "Thing", "name": "Shared calendar apps" }
  ]
}
</script>
```

Mirror this on `/blog/` (EN) too — `inLanguage: "en"`.

---

### M4 — Link from homepages to top blog posts
**Impact:** Internal link equity flow to your highest-traffic potential pages; better crawl depth.
**Effort:** Small
**Confidence:** Confirmed

On EN home, add a "From the blog" or "Resources" section linking to:
- `/blog/best-household-apps-for-couples-2026`
- `/blog/shared-calendar-for-couples`
- `/blog/cozi-alternatives-2026`
- `/blog/miiro-vs-cozi-vs-cupla`

On NL home, the analogues:
- `/nl/blog/beste-huishoud-apps`
- `/nl/blog/gedeelde-agenda-app-koppels`
- `/nl/blog/cozi-app-nederlands`
- `/nl/blog/klender-vs-miiro`

---

### M5 — Audit blog post schema for Article completeness
**Impact:** AI citation eligibility (E-E-A-T signals).
**Effort:** Medium (touches all blog posts; templating-friendly)
**Confidence:** Likely (spot-check only)

Sample (`/blog/shared-calendar-for-couples`) has 1 JSON-LD block, presumably `Article`. Verify each post includes:
- `@type: Article` (or `BlogPosting`)
- `headline` (matches `<title>` ≤110 chars)
- `author` — `Person` with `name`, ideally `url`
- `publisher` — `Organization` with `name`, `logo`
- `datePublished` / `dateModified` (ISO 8601)
- `mainEntityOfPage`
- `image` (1200×630 absolute URL, ideally page-specific)

Also add `BreadcrumbList` to every post:
```
Home > Blog > {Post title}
```

---

### M6 — Expand homepage prose for topical signal
**Impact:** Medium for keyword ranking; medium-high for GEO answer extraction.
**Effort:** Medium (copywriting)
**Confidence:** Likely

Add a 150–250 word section under the hero on both homepages with prose like:

EN: "Miiro is a household management app for couples and families. Tell Sam what your household needs in plain language — 'Pick up Miles at 3, milk on the list, dinner tomorrow?' — and Sam sorts it into tasks, calendar events, meal plans, and a grocery cart automatically. Built for the kind of mental load that doesn't fit a checklist..."

NL: equivalent in Dutch.

This gives crawlers and AI engines extractable paragraphs about your value proposition. Short, punchy hero copy is great for conversion but **thin** for SEO.

---

### M7 — Shorten NL `<title>` to fit Google SERP
**Impact:** Reduces truncation in Google SERP (currently 65 chars, recommended ≤60).
**Effort:** Trivial
**Confidence:** Confirmed

Option A: `Miiro · Vertel Sam wat je huishouden nodig heeft` (47 ch — drops "Hij regelt het")
Option B: `Miiro - Huishoud app voor koppels. Sam regelt het.` (51 ch — leads with category)
Option C: keep current — minor truncation is acceptable

Test in [Google SERP simulator](https://www.mangools.com/free-seo-tools/serp-simulator) before changing.

---

## 🔵 Low Priority (when convenient)

### L1 — Add more AI crawlers to robots.txt
```
User-agent: Applebot-Extended
Allow: /

User-agent: CCBot
Allow: /

User-agent: Diffbot
Allow: /

User-agent: Bytespider
Allow: /

User-agent: YouBot
Allow: /
```

Adding `Disallow: /` for any you'd rather block, but you currently want maximum discoverability — keep them all on.

### L2 — Reconsider EN home title
Current: "Miiro. Tell Sam what your household needs. It does it." (54 ch — strong)
Alternative: "Miiro — Household app for couples. Sam handles it." (52 ch, more searchable for "household app")
Probably keep as-is — brand-led title is fine and "Sam" reinforces brand entity.

### L3 — Add `inLanguage` to NL Organization
```json
{
  "@type": "Organization",
  "name": "Miiro",
  "inLanguage": ["en", "nl"],
  ...
}
```
Very minor — Organization isn't a language-specific entity, so not strictly necessary.

### L4 — When you have App Store reviews, add aggregateRating
Strong AI citation signal. Example:
```json
{
  "@type": "SoftwareApplication",
  "aggregateRating": {
    "@type": "AggregateRating",
    "ratingValue": "4.8",
    "ratingCount": "127"
  }
}
```
**Do not fabricate** — only ship once you have real App Store review data.

### L5 — NL Organization sameAs
If you launch Dutch-specific social handles, add them. Otherwise leave as-is.

---

## GEO Specific — Get cited in ChatGPT / Perplexity / Claude / Gemini

Beyond H4 (`llms.txt`) and H2 (FAQPage on EN), the highest-ROI GEO improvements:

1. **Build a `/about` page** with structured Org info — founder name, location, mission. AI engines cite "about" content heavily.
2. **Get into competitor comparison content elsewhere.** Cozi alternatives, AnyList alternatives, Cupla alternatives lists on third-party sites are direct GEO surfaces. The fact that `/blog/cozi-alternatives-2026` exists on your domain is good — also pitch to Reddit r/productivity, r/marriage, NL r/Netherlands threads.
3. **`mentions` schema on blog posts.** Articles comparing Miiro to Cozi/Cupla/Klender should explicitly list `mentions` of each named entity:
   ```json
   "mentions": [
     { "@type": "SoftwareApplication", "name": "Cozi", "url": "https://www.cozi.com" },
     { "@type": "SoftwareApplication", "name": "Cupla", "url": "https://cupla.app" },
     { "@type": "SoftwareApplication", "name": "Klender", "url": "https://klender.com" }
   ]
   ```
4. **Author profiles (`ProfilePage` schema).** AI engines weight authored content over anonymous. If team members write blog posts, give them author pages.
5. **Update `datePublished` / `dateModified` honestly.** AI engines penalize stale content. "(2026)" in your titles only works if `dateModified` is in 2026.

---

## Dutch-Market-Specific (EN-focused advice would miss these)

1. **Keep `hreflang="nl"` not `nl-NL`.** Plain `nl` covers both Netherlands and Flanders. Switch to `nl-NL` only if you launch separate Belgian content (`/be/`).
2. **Klender is the local competitor that matters.** Your `klender-vs-miiro` and `klender-alternatieven` posts are correctly targeted — invest more there. Add `SoftwareApplication` mentions schema (see GEO #3).
3. **Albert Heijn is the #1 entity** in Dutch grocery queries. Your NL FAQ schema mentions it explicitly — keep it there, also add it to the EN copy if your US storefront integrates with a US grocer (Instacart? Whole Foods?). AI engines treat these as proof of capability.
4. **Picnic is a uniquely-Dutch entity.** Mention this in marketing copy too — "Werkt met Picnic" is a Dutch differentiator no US app can claim.
5. **Bol.com / Coolblue** are the Dutch retail benchmarks for trust signals. Citing them isn't relevant for your app, but **review pages** from Dutch tech reviewers (Tweakers, Bright, NU.nl Tech) carry domain authority weight in NL Google. Pursue reviews there.
6. **`.nl` is more trusted than `.app` in NL.** You'll never get the `miiro.nl` cachet from `miiro.app`, but that's a non-issue if your content quality + entity mentions are strong. Don't migrate domains.
7. **"Belastingdienst"-style civic Dutch** isn't your voice — your NL copy ("Vertel Sam wat je huishouden nodig heeft. Hij regelt het.") is naturally conversational and right for the segment.
8. **Tweakers.net** is the #1 Dutch tech publication. If they review Miiro, your domain authority will measurably rise. Worth pitching directly.

---

## Quick wins checklist (1-hour total)

Pick these up first — all trivial, all confirmed, total impact > 15 min effort each:

- [ ] Fix `og:url` EN trailing slash (H5)
- [ ] Add `og:site_name` to EN (M1)
- [ ] Tighten HSTS header (M2)
- [ ] Ship `/llms.txt` (H4)
- [ ] Add 4 more AI crawler allows to `robots.txt` (L1)
- [ ] Add CollectionPage schema to `/blog/` and `/nl/blog/` (M3)

After those: tackle H1 (blog hreflang), H2 (EN schema parity), H3 (CSP) in order. Those three move the score from 84 → ~92.

End of plan.
