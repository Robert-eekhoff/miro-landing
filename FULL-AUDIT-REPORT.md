# Miiro SEO Audit — `miiro.app` (EN + NL)

**Audit date:** 2026-05-14
**Scope:** `https://miiro.app/` (EN) + `https://miiro.app/nl/` (NL) homepages, with spot checks across blog, sitemap, robots, sample post pairs
**Method:** LLM-first analysis on directly-fetched HTML, with deterministic verification scripts where possible. Some sub-scripts blocked by missing `beautifulsoup4` and `pip`; manual regex-based parsing substituted with documented confidence labels.
**Mode:** Investigation only — no files modified.

---

## Executive Summary

Miiro's two-locale rollout is in **good shape**. Hreflang on the two homepages is correctly bidirectional + self-referencing + carries `x-default`. Pricing parity between visible copy and JSON-LD is intact in both locales. Open Graph images (EN: 41KB, NL: 48KB, both 1200×630) load. Security headers score 85/100. Robots explicitly allows all major AI crawlers.

The site is **not** suffering from any critical SEO regression from today's deploy.

The most consequential gaps are **structural asymmetries between EN and NL** and **blog hreflang declared only in the sitemap, not in HTML heads**. Fixing those plus a few GEO-readiness items would meaningfully tighten the international setup and AI-search discoverability.

**Score (estimated, LLM-first):**

| Category | Score | Notes |
|---|---|---|
| Technical SEO | 88 | Clean. Missing in-HTML hreflang on blog posts; minor canonical/og:url inconsistency |
| On-Page | 92 | Titles, descriptions, H1/H2 hierarchy, lang attributes all correct |
| Schema / Structured Data | 80 | NL is richer than EN (FAQPage + WebPage + foundingLocation). EN homepage parity gap |
| Hreflang (international) | 82 | Homepages perfect; blog posts missing in-HTML alternates |
| Content | 85 | Strong localization (AH/Jumbo, NL pricing format, Amsterdam) |
| Performance | n/a | PSI returned no metrics (cache/quota); curl TTFB excellent (~60ms EU edge) |
| Security headers | 85 | HSTS, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy ✓; CSP missing |
| GEO / AI-search readiness | 70 | Robots ✓, FAQ on NL ✓, but no llms.txt; EN missing FAQ; no Article schema in NL blog index |

**Overall: 84/100 — Good.**

---

## Methodology & Environment Limitations

- ✅ Direct fetch of all target HTML (EN home, NL home, NL blog index, 1 EN blog post, 1 NL blog post, 5 sample post pairs).
- ✅ Sitemap fully parsed (58 URLs total; 36 EN, 22 NL).
- ✅ Headers, robots.txt, llms.txt, og:image GET-verified.
- ✅ JSON-LD parsed and validated structurally.
- ✅ Security headers via `security_headers.py`.
- ⚠️ **PageSpeed Insights** returned `null` metrics for both URLs — likely insufficient CrUX field data (site is brand-new on this domain configuration) and the lab-side response truncated. Performance findings carry **Likely** confidence. Recommend running PSI manually in a browser or via the dashboard.
- ⚠️ **`hreflang_checker.py`, `social_meta.py`, `broken_links.py`** require `beautifulsoup4`; `pip` is not available on this Python install. Substituted with regex parsing for the same evidence.
- ✅ All findings labeled **Confirmed / Likely / Hypothesis**.

---

## 1. Technical SEO

### 1.1 Indexability & crawl

| Element | EN (`/`) | NL (`/nl/`) | Status |
|---|---|---|---|
| HTTP status | 200 | 200 | ✅ |
| `x-vercel-cache` | HIT | HIT | ✅ |
| `cache-control` | `public, max-age=0, must-revalidate` | same | ✅ Vercel-standard for HTML |
| `meta robots` | not present (implicit `index,follow`) | not present | ✅ |
| `<html lang>` | `en` | `nl` | ✅ |
| Canonical | `https://miiro.app/` | `https://miiro.app/nl/` | ✅ |
| TTFB (Frankfurt edge) | 63 ms | 55 ms | ✅ Excellent |

### 1.2 robots.txt

```
User-agent: *  Allow: /
GPTBot, ChatGPT-User, PerplexityBot, ClaudeBot, anthropic-ai, Google-Extended all explicitly Allow: /
Sitemap: https://miiro.app/sitemap.xml
```

**Finding (Confirmed):** Explicit allowlist for AI crawlers is excellent for GEO. ✅
**Gap (Confirmed):** No directive for **Applebot-Extended**, **Bytespider**, **CCBot**, **Google-Extended is listed, but Googlebot-Extended is not a real bot name — `Google-Extended` is correct**, **Diffbot**, **YouBot**, **Bingbot** (implied via `*` but explicit is safer). Low-impact additions worth considering.

### 1.3 Sitemap

**Confirmed evidence:** `sitemap.xml` lists 58 URLs (36 EN + 22 NL). NL homepage and blog index are both included. Hreflang `xhtml:link` alternates are declared in the sitemap for the 2 homepages + 14 of the 36 EN blog posts (those with NL counterparts).

**Issue (Confirmed):** Hreflang alternates declared in the **sitemap only** — not in the HTML `<head>` of blog posts. Google supports either, but in-page declarations are stronger, more often respected, and easier to audit. See §3.2.

### 1.4 Redirects

Both URLs return 200 directly with no intermediate hop. `https://miiro.app/nl/` (with trailing slash) is the canonical. No redirect chain detected.

### 1.5 Response headers (security)

```
strict-transport-security: max-age=63072000           ✅
x-content-type-options: nosniff                       ✅
x-frame-options: DENY                                 ✅
referrer-policy: strict-origin-when-cross-origin      ✅
permissions-policy: camera=(), microphone=(), geolocation=()   ✅
content-security-policy: ❌ MISSING
```

**Score:** 85/100 (from `security_headers.py`).

**Findings:**
- 🔴 **Content-Security-Policy missing.** (Confirmed.) Impacts both XSS resilience and Google's Best Practices Lighthouse score. Inline `<style>` and inline `<script>` are present, so CSP needs `'unsafe-inline'` carve-outs or hashing — non-trivial.
- ⚠️ **HSTS missing `includeSubDomains` and `preload`.** (Confirmed.) Current: `max-age=63072000`. Recommended: `max-age=63072000; includeSubDomains; preload`. Eligible to submit to the HSTS preload list once both are set.

---

## 2. On-Page SEO

### 2.1 EN homepage `/`

| Element | Value | Length | Verdict |
|---|---|---|---|
| `<title>` | "Miiro. Tell Sam what your household needs. It does it." | 54 ch | ✅ Within 50–60 sweet spot |
| `<meta description>` | "Miiro is your invisible domestic partner. From grocery runs to meal planning, just speak your mind, and the work gets done." | 132 ch | ✅ Within 120–160 |
| `<h1>` | "Tell Sam what your household needs. It does it." | 1 | ✅ |
| `<h2>` × 5 | "One sentence. Sam handles the rest." / "Paste a link. Get the recipe." / "Not a list. A real order." / "One household. Always in sync." / "Try Miiro for 7 days." | 5 | ✅ Good hierarchy |
| Word count (rendered text) | ~629 words | — | ⚠️ Thin for a flagship landing page; lots of demo UI in DOM but limited prose for ranking |
| `<img alt>` | 3 imgs (2 decorative empty alt = logo + 1 alt="Miiro") | — | ✅ Acceptable (page is icon/UI-heavy, not photo-heavy) |

### 2.2 NL homepage `/nl/`

| Element | Value | Length | Verdict |
|---|---|---|---|
| `<title>` | "Miiro - Vertel Sam wat je huishouden nodig heeft. Hij regelt het." | 65 ch | ⚠️ Slightly long (will truncate to ~60 in Google SERP); acceptable |
| `<meta description>` | "Miiro is je onzichtbare huishoudpartner. Van boodschappen tot maaltijdplanning, zeg het en het werk wordt gedaan." | 124 ch | ✅ |
| `<h1>` | "Vertel Sam wat je huishouden nodig heeft. Hij regelt het." | 1 | ✅ |
| `<h2>` × 5 | Localized counterparts to EN | 5 | ✅ |
| Word count | ~633 words | — | ⚠️ Same density issue |
| `<img alt>` | Identical pattern to EN | — | ✅ |

### 2.3 Open Graph & Twitter

| Field | EN | NL | Verdict |
|---|---|---|---|
| `og:title` | "Miiro. Tell Sam what your household needs." | "Miiro. Vertel Sam wat je huishouden nodig heeft." | ✅ Both localized |
| `og:description` | EN copy | NL copy | ✅ |
| `og:image` | `/og-image.png` (1200×630, 41 KB, valid PNG) | `/og-image-nl.png` (1200×630, 48 KB, valid PNG) | ✅ Both load; correct dimensions |
| `og:url` | `https://miiro.app` (**no trailing slash**) | `https://miiro.app/nl/` | ⚠️ EN inconsistent with canonical `https://miiro.app/` |
| `og:type` | website | website | ✅ |
| `og:locale` / alt | en_US / nl_NL | nl_NL / en_US | ✅ |
| `og:site_name` | **MISSING** | "Miiro" | ⚠️ Asymmetric — EN should include it |
| `twitter:card` | summary_large_image | summary_large_image | ✅ |
| `twitter:image` | `/og-image.png` | `/og-image-nl.png` | ✅ |

---

## 3. Hreflang Validation (CRITICAL — fresh deploy)

### 3.1 Homepage triplet — ✅ PASS

Both homepages carry the same self-consistent set:

```html
<link rel="alternate" hreflang="en" href="https://miiro.app/">
<link rel="alternate" hreflang="nl" href="https://miiro.app/nl/">
<link rel="alternate" hreflang="x-default" href="https://miiro.app/">
```

**Validated (Confirmed):**
- ✅ Bidirectional: EN points to NL, NL points to EN.
- ✅ Self-referencing: each page declares itself in its own hreflang block.
- ✅ `x-default` present on both, pointing to canonical EN.
- ✅ Canonical and hreflang agree (EN canonical = EN hreflang, NL canonical = NL hreflang).
- ✅ Language codes are valid ISO 639-1 (`en`, `nl`).
- ⚠️ Both locales use plain `en` and `nl` (no region suffix like `en-US` / `nl-NL`). This is **correct** for language targeting without regional bias — keep as-is unless you later add `en-GB`, `nl-BE`, etc.

### 3.2 Blog posts — ⚠️ Hreflang declared in sitemap only

**Evidence (Confirmed):** Sampled 5 post pairs (3 NL, 2 EN). Every blog post's HTML `<head>` contains **only** `<link rel="canonical">` — **no `<link rel="alternate" hreflang>` tags at all**.

- `/blog/shared-calendar-for-couples` → canonical only, no hreflang in head
- `/nl/blog/cozi-app-nederlands` → canonical only, no hreflang in head
- `/nl/blog/mentale-belasting-huishouden` → same
- `/nl/blog/maaltijdplanning-voor-twee` → same
- `/nl/blog/beste-huishoud-apps` → same
- `/blog/best-household-apps-for-couples-2026` → same
- `/blog/meal-planning-for-couples-guide` → same

Sitemap **does** declare these via `xhtml:link` alternates. Per Google docs, sitemap-only hreflang is **valid**, but in-page tags are:
- Crawled and applied **faster** (no need to wait for sitemap re-crawl)
- Subject to **fewer mismatches** (one declaration source, attached to the page itself)
- Easier to audit and debug

**Impact (Likely):** Without in-page hreflang, Google may take longer to identify the EN↔NL pairing for your 14 paired blog posts, and Bing/Yandex/Baidu (which weight sitemap hreflang less) may miss the relationship entirely.

### 3.3 Blog index pages — ✅ PASS

`/blog/` and `/nl/blog/` both carry the full hreflang triplet in HTML head. ✅

### 3.4 NL-only blog posts — correct behavior

7 of 20 NL blog posts have no EN counterpart (e.g., `klender-vs-miiro`, `klender-alternatieven`, `timetree-alternatief`, `weekmenu-maken-tips`, `google-agenda-delen-partner`, `apps-samenwonen`, `app-tips-druk-gezinsleven`). These correctly omit hreflang in the sitemap. ✅ This is the right call — don't pair them with random EN pages.

---

## 4. Schema / Structured Data

### 4.1 EN homepage JSON-LD

**Single `<script>` block with `@graph`:**
- `Organization` — name, url, logo, sameAs (Instagram, TikTok). No `foundingLocation`.
- `SoftwareApplication` — name, operatingSystem=iOS, applicationCategory=LifestyleApplication, installUrl, **2 Offers (9.99 USD monthly, 59.99 USD annual)**.

**Missing on EN homepage vs NL:**
- ❌ No `WebPage` node
- ❌ No `FAQPage` node
- ❌ No `inLanguage` on SoftwareApplication
- ❌ No `foundingLocation` on Organization

### 4.2 NL homepage JSON-LD

**Single block with `@graph`:**
- `Organization` — includes `foundingLocation: Amsterdam, Netherlands` ✅
- `WebPage` — with `inLanguage: "nl"`, `isPartOf: WebSite` ✅
- `SoftwareApplication` — with `inLanguage: ["en","nl"]`, NL App Store install URL, **2 Offers (9.99 EUR monthly, 59.99 EUR annual)**
- `FAQPage` — 8 Q&As covering: what is Tell Miiro, free trial pricing, partner pricing, supermarket integration (AH/Jumbo/Picnic/Crisp/Plus), Dutch language support, recipe import, data security, vs Google/Apple Calendar

### 4.3 Pricing parity check — ✅ CONFIRMED

| Locale | Visible copy | JSON-LD | Match |
|---|---|---|---|
| EN | "$9.99 /month", "$59.99 /year", "Equivalent to $5/month" | 9.99 USD monthly, 59.99 USD annual | ✅ |
| NL | "€9,99 /maand", "€59,99 /jaar", "Komt neer op €5,00 per maand" | 9.99 EUR monthly, 59.99 EUR annual | ✅ |
| FAQ NL text | "9,99 euro per maand of 59,99 euro per jaar" | matches | ✅ |

Decorative price tokens like `€16,46` and `€0,00` are recipe-cart UI demos — not real pricing. Not a parity issue.

### 4.4 FAQPage on NL — informational note

Per Google's August 2023 update, FAQ rich results are **restricted to government and health authorities**. Commercial sites can still ship FAQPage schema, but it will **not** trigger rich results in Google SERP. It **is** still consumed by:
- Perplexity, ChatGPT browse, Claude search, Bing — as answer-extractable structured Q&A
- Google's AI Overview for entity grounding

**Recommendation:** Keep the NL FAQPage for GEO value, but understand it won't produce a SERP rich result.

### 4.5 Schema gaps (cross-cutting)

- ❌ No `BreadcrumbList` on blog posts or blog index
- ❌ No `Blog` or `CollectionPage` on `/blog/` or `/nl/blog/`
- ❌ EN blog posts have `Article` schema (good), but missing `author`, `publisher` may be incomplete — not audited fully here
- ✅ Sample EN blog post (`shared-calendar-for-couples`) has 1 JSON-LD block (Article).
- ⚠️ `/nl/blog/` (index) has **0 JSON-LD blocks** → missing `CollectionPage` or `Blog` schema

---

## 5. Content / Localization

### 5.1 Dutch localization quality — ✅ Excellent

| Signal | Evidence |
|---|---|
| Number format | `€9,99` (comma decimal, NL standard) ✅ |
| Currency | EUR throughout NL ✅ |
| Supermarket entities | Albert Heijn, Jumbo, Picnic, Crisp, Plus — all major NL grocers ✅ |
| Cultural reference | "Klender" (Dutch competitor) — own blog posts written about it ✅ |
| Geographic anchor | `foundingLocation: Amsterdam, Netherlands` on NL Organization ✅ |
| Time format | "om 15:00" (24-hour) in demo copy ✅ |
| Pronoun | Sam = "Hij" (masculine) — consistent in NL copy ✅ |
| FAQ uses NL-specific concerns | Dutch-language support, partner cost, supermarket integration ✅ |

### 5.2 Word density

Both homepages: ~630 words of rendered text. This is **thin** for a flagship landing page. Most of the DOM weight is decorative demo UI (cart animations, recipe cards) which is great for conversion but does **not** add ranking-relevant text content.

**Likely** (medium confidence): Adding a 150–250 word "How Miiro works" or "Why couples choose Miiro" section under the hero would meaningfully strengthen on-page topical signals.

### 5.3 Internal linking

| Page | Internal links | Notes |
|---|---|---|
| EN home | 8 internal | 6 unique: `/`, `/blog`, `/nl/`, `/privacy`, `/support`, `/terms` |
| NL home | 8 internal | 6 unique: `/`, `/nl/`, `/nl/blog`, `/privacy`, `/support`, `/terms` |

**Gap (Confirmed):** Each homepage links only to its blog **index**, not to specific high-value posts. The "best apps for couples", "Klender vs Miiro", "Cozi alternatives" posts are the ones likely to attract organic traffic — link to them from homepage.

**Gap (Confirmed):** NL homepage **does not** link to `/privacy` / `/support` / `/terms` localized versions (because those are EN-only). For a Dutch user, that's a UX/legal nuance — minor, but worth noting.

### 5.4 /nl/blog/ vs /nl/ — no conflict detected

- `/nl/` canonical = `/nl/`
- `/nl/blog/` canonical = `/nl/blog/`
- No content overlap (different `<title>` and `<description>`).
- `/nl/blog/` correctly carries its own hreflang triplet pointing to `/blog/`.
- ✅ No risk of `/nl/blog/` competing with `/nl/` for the same query.

---

## 6. GEO / AI Search Readiness

### 6.1 What's working

- ✅ Robots.txt explicitly allows GPTBot, ChatGPT-User, PerplexityBot, ClaudeBot, anthropic-ai, Google-Extended.
- ✅ NL FAQPage schema (great for ChatGPT/Perplexity answer extraction).
- ✅ Strong, consistent brand entity ("Sam = AI assistant").
- ✅ Sitemap is current (lastmod 2026-05-14).
- ✅ Clean semantic HTML (`<h1>`, `<h2>` hierarchy).
- ✅ Albert Heijn / Jumbo / Picnic mentioned in NL FAQ — entity-rich for Dutch market queries.

### 6.2 Gaps

| Item | Status | Impact |
|---|---|---|
| `/llms.txt` | ❌ 404 | High for GEO — emerging standard (Anthropic, Mistral, others reference it) |
| EN FAQPage schema | ❌ Missing on home | Medium — losing entity-extractable Q&A for English AI answers |
| `WebPage` schema on EN home | ❌ Missing | Low-Medium — small but helpful structured anchor |
| `Article` author + publisher on blog posts | ⚠️ Not verified | Likely missing — important for AI-citation E-E-A-T |
| Long-form How-To prose on landing | ⚠️ Thin | Medium — AI answer engines extract paragraphs; short, demo-heavy pages get cited less |
| `SoftwareApplication.review` / `aggregateRating` | ❌ Missing | Medium — strong AI citation signal once you have real reviews |

### 6.3 GEO opportunity — target queries

For the queries you flagged ("household apps for couples", "shared calendar apps"):

1. **`/blog/best-household-apps-for-couples-2026`** (exists, ranked well — make sure it has Article + BreadcrumbList + author + publisher schema).
2. **`/blog/shared-calendar-for-couples`** (exists with NL counterpart). Add `mentions` or `about` schema linking to entities: Google Calendar, Apple Calendar, Cozi, Cupla.
3. **Comparison pages** (`cozi-alternatives`, `cupla-alternatives`, `anylist-vs-cozi`) — these are exactly the queries Perplexity/ChatGPT fan-out into when users ask "what's the best X". Add `ItemList` schema with each compared app as a `SoftwareApplication`.
4. Build an `/llms.txt` listing: Organization, app description, key features, pricing, blog index. (One file, ~50 lines, big payoff.)

---

## 7. Performance

**PSI returned no metrics** for either URL (likely CrUX field data insufficient + Lab response truncated by API). Lab + field measurement is the most reliable next step.

**Likely** (medium confidence) based on raw HTML inspection:

| Signal | Observation | Implication |
|---|---|---|
| TTFB (curl, Frankfurt edge) | EN 63 ms, NL 55 ms | ✅ Excellent server response |
| HTML size | EN 113 KB, NL 117 KB | ⚠️ Large for landing page — inline CSS + inline JS is substantial |
| Render-blocking | Google Fonts CSS not `font-display: swap` configured externally (relying on Google's URL) | ⚠️ Possible LCP risk on slow connections |
| GSAP + ScrollTrigger | `defer` ✅ | ✅ Good — won't block LCP |
| GA4 | Loads only after consent ✅ | ✅ Good for performance + privacy |
| Vercel cache | HIT both pages ✅ | ✅ Edge cached |

**Recommend:** Open Chrome DevTools Lighthouse on both URLs manually OR run `npx unlighthouse-cli scan https://miiro.app/` for full lab data. PSI quota may also reset; retry once.

---

## 8. Broken Links

Sample-based (manual): all internal links from EN/NL homepages (`/`, `/nl/`, `/blog`, `/nl/blog`, `/privacy`, `/support`, `/terms`) resolve. App Store, Instagram, TikTok external links structurally valid. No broken-link scan run at scale (`broken_links.py` blocked by missing dependency). **Confidence: Likely.**

---

## 9. Findings Summary — by Severity

### 🔴 Critical (0)
*No critical issues. The deploy is solid.*

### ⚠️ High (5)

| # | Finding | Confidence | Affects |
|---|---|---|---|
| H1 | Blog posts have no in-HTML hreflang — sitemap-only declaration | Confirmed | All paired blog posts (~14 EN, ~10 NL) |
| H2 | EN homepage missing FAQPage, WebPage, and Organization.foundingLocation that NL has | Confirmed | EN home schema parity |
| H3 | Content-Security-Policy header missing | Confirmed | All pages |
| H4 | No `/llms.txt` (GEO standard) | Confirmed | Site-wide GEO |
| H5 | `og:url` on EN home = `https://miiro.app` (no trailing slash) vs canonical `https://miiro.app/` — small inconsistency | Confirmed | EN home only |

### 🟡 Medium (7)

| # | Finding | Confidence | Affects |
|---|---|---|---|
| M1 | `og:site_name` missing on EN home (present on NL) | Confirmed | EN home OG |
| M2 | HSTS lacks `includeSubDomains` and `preload` | Confirmed | All pages |
| M3 | `/nl/blog/` index has 0 JSON-LD (no Blog/CollectionPage schema) | Confirmed | NL blog hub |
| M4 | Homepage internal linking — neither home links to deep blog posts | Confirmed | Internal link equity flow |
| M5 | Sample EN blog post has only Article schema — likely no BreadcrumbList, may be missing author/publisher | Likely (not exhaustively verified) | Blog SEO |
| M6 | Word count on both homepages ~630 — thin for landing page topical signal | Confirmed | Both homes |
| M7 | NL `<title>` is 65 chars — will truncate in Google SERP | Confirmed | NL home |

### 🔵 Low (5)

| # | Finding | Confidence | Affects |
|---|---|---|---|
| L1 | Robots.txt doesn't explicitly list Applebot-Extended, Bytespider, CCBot, Diffbot | Confirmed | GEO breadth |
| L2 | EN home `<title>` includes "Sam" — strong brand, but consider also including "couples" or "household app" for search match | Hypothesis | EN home title |
| L3 | NL home lacks `inLanguage` on Organization (NL JSON-LD has it on SoftwareApplication/WebPage but not Organization) | Likely | NL schema |
| L4 | No `aggregateRating` or `review` on SoftwareApplication — strong AI citation signal when populated | Confirmed missing | Both homes |
| L5 | NL Organization mentions only `instagram.com/miiroapp`, `tiktok.com/@miiroapp` — same as EN. Consider adding `sameAs: https://miiro.app/nl/` or NL social handles when available | Confirmed | NL Organization sameAs |

### ✅ Notable wins (passing checks worth keeping)

- Hreflang triplet on both homepages — bidirectional, self-referencing, with x-default. ✅
- Pricing parity between visible copy and JSON-LD on both locales. ✅
- og:image (1200×630, valid PNG) loads on both. ✅
- Robots.txt explicitly allows ALL major AI crawlers. ✅
- Security score 85/100 with HSTS, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy. ✅
- TTFB <70ms from EU edge on both. ✅
- Vercel cache HIT both pages. ✅
- `lang="en"` / `lang="nl"` correctly set. ✅
- Single H1 per page; clean H2 structure (5 each). ✅
- Strong, comprehensive 8-Q FAQ schema on NL. ✅
- Dutch localization quality is genuinely excellent (currency format, supermarket entities, pronoun consistency, "Klender" coverage). ✅

---

## 10. Dutch-Market-Specific Notes (EN-focused SEO would miss)

1. **`Klender` is the right entity to target.** EN-focused tooling won't know Klender (Dutch calendar app) is your direct local competitor. Your `klender-vs-miiro` and `klender-alternatieven` posts are well-positioned. Add `mentions` schema linking to Klender as an entity.
2. **Albert Heijn / Jumbo / Picnic are first-class search entities** in NL. The fact they appear in your NL FAQ schema is **strongly** positive for GEO — Dutch users asking ChatGPT "kan ik bij Albert Heijn bestellen via app X" will pull from this.
3. **Comma decimal separator (€9,99 not €9.99).** Already correct in visible copy. Note: JSON-LD `price` must remain `"9.99"` (Schema.org requires period decimal). This is correct. Don't "fix" it.
4. **Title slightly long for SERP.** Dutch words tend to be longer than English equivalents — the 65-char NL title is borderline. Consider: "Miiro · Vertel Sam wat je huishouden nodig heeft" (47 ch, drops "Hij regelt het").
5. **`nl-NL` vs `nl-BE`.** Currently using plain `nl` which targets both Netherlands and Flanders. If you want to specifically target Dutch in the Netherlands (excluding Belgium), switch to `hreflang="nl-NL"`. Keep `nl` if you want Flanders too. Lighthouse won't flag this; intentional.
6. **`/nl/` URL pattern** is industry-standard. Don't switch to `.nl` TLD or `nl.miiro.app` — current structure is optimal and consolidates link equity.
7. **GTM/GA4 cookie consent on NL is GDPR-essential.** Currently you load GA4 only after consent — ✅ confirmed correct in code.

---

## 11. Artifacts

- `FULL-AUDIT-REPORT.md` — this file
- `ACTION-PLAN.md` — prioritized fix list (separate file)
- Raw fetched HTML at `/tmp/miiro-seo/` (en.html, nl.html, nl-blog-index.html, blog-en.html, og-image.png, og-image-nl.png)

End of report.
