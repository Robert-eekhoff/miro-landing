#!/usr/bin/env python3
"""Generate sitemap.xml (index) + sitemap-en.xml + sitemap-nl.xml from the filesystem.

Run from the repo root:  python3 scripts/generate-sitemap.py

Why this exists: the sitemap used to be hand-maintained, so <lastmod> went stale
(18 URLs still claimed 2026-03-17 in September) and Google stopped re-reading it.
Dates here come from the file's last git commit, so they move whenever content does.
"""

import os
import re
import subprocess
import sys
from datetime import date

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BASE = "https://miiro.app"

# Pages that exist but should stay out of search: transactional, auth and deep-link
# landing pages, plus low-commercial posts we don't want competing for crawl budget.
EXCLUDE = {
    "grocery-done.html",
    "h.html",
    "join.html",
    "tiktok.html",
    "blog/how-we-built-miiro.html",
    "blog/lessons-learned-building-miiro.html",
    "blog/wine-pairing-with-sam.html",
}
EXCLUDE_DIRS = {"auth", "api", "assets", "scripts", "skills", ".well-known", ".git", ".vercel"}

# English path -> Dutch path. Everything here gets a reciprocal hreflang set.
# Dutch pages with no English twin are emitted with nl + x-default pointing at themselves.
PAIRS = {
    "/": "/nl/",
    "/blog/": "/nl/blog/",
    "/blog/best-household-apps-for-couples-2026": "/nl/blog/beste-huishoud-apps",
    "/blog/how-to-reduce-mental-load-in-your-relationship": "/nl/blog/mentale-belasting-huishouden",
    "/blog/meal-planning-for-couples-guide": "/nl/blog/maaltijdplanning-voor-twee",
    "/blog/shared-calendar-for-couples": "/nl/blog/gedeelde-agenda-app-koppels",
    "/blog/shared-grocery-list-apps-2026": "/nl/blog/boodschappenlijst-app-vergelijken",
    "/blog/what-is-tell-miiro-ai-household-management": "/nl/blog/ai-assistent-huishouden",
    "/blog/household-management-for-couples": "/nl/blog/huishouden-organiseren-als-koppel",
    "/blog/moving-in-together-checklist": "/nl/blog/samenwonen-checklist",
    "/blog/how-to-save-recipes-tiktok-instagram-youtube": "/nl/blog/recepten-opslaan-tiktok-instagram",
    "/blog/couples-sunday-reset-routine": "/nl/blog/zondag-reset-routine",
    "/blog/cozi-alternatives-2026": "/nl/blog/cozi-app-nederlands",
    "/blog/apps-every-couple-needs-2026": "/nl/blog/beste-apps-voor-koppels",
    "/blog/how-to-organize-household-tasks": "/nl/blog/taken-verdelen-met-partner",
}
NL_TO_EN = {v: k for k, v in PAIRS.items()}


def url_path(relpath):
    """blog/foo.html -> /blog/foo ; blog/index.html -> /blog/ ; index.html -> /"""
    if relpath == "index.html":
        return "/"
    if relpath.endswith("/index.html"):
        return "/" + relpath[: -len("index.html")]
    return "/" + relpath[: -len(".html")]


def lastmod(relpath):
    """Last git commit date for the file, falling back to mtime."""
    try:
        out = subprocess.run(
            ["git", "log", "-1", "--format=%cs", "--", relpath],
            cwd=ROOT, capture_output=True, text=True, timeout=15,
        ).stdout.strip()
        if re.fullmatch(r"\d{4}-\d{2}-\d{2}", out):
            return out
    except Exception:
        pass
    ts = os.path.getmtime(os.path.join(ROOT, relpath))
    return date.fromtimestamp(ts).isoformat()


def collect():
    pages = []
    for dirpath, dirnames, filenames in os.walk(ROOT):
        dirnames[:] = [d for d in dirnames if d not in EXCLUDE_DIRS and not d.startswith(".")]
        for name in filenames:
            if not name.endswith(".html"):
                continue
            rel = os.path.relpath(os.path.join(dirpath, name), ROOT)
            if rel in EXCLUDE:
                continue
            pages.append(rel)
    return sorted(pages)


def alternates(path):
    """Return the hreflang set for a path, or None if the page is standalone."""
    if path in PAIRS:
        en, nl = path, PAIRS[path]
    elif path in NL_TO_EN:
        en, nl = NL_TO_EN[path], path
    elif path.startswith("/nl/"):
        # Dutch-only page: declare itself for nl and x-default so Google still
        # sees an explicit language signal.
        return [("nl", path), ("x-default", path)]
    else:
        return None
    return [("en", en), ("nl", nl), ("x-default", en)]


def url_block(path, mod):
    lines = ["  <url>", f"    <loc>{BASE}{path}</loc>", f"    <lastmod>{mod}</lastmod>"]
    alts = alternates(path)
    if alts:
        for lang, target in alts:
            lines.append(
                f'    <xhtml:link rel="alternate" hreflang="{lang}" href="{BASE}{target}" />'
            )
    lines.append("  </url>")
    return "\n".join(lines)


def write_urlset(filename, entries):
    body = "\n".join(url_block(p, m) for p, m in entries)
    doc = (
        '<?xml version="1.0" encoding="UTF-8"?>\n'
        '<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9"\n'
        '        xmlns:xhtml="http://www.w3.org/1999/xhtml">\n'
        f"{body}\n"
        "</urlset>\n"
    )
    with open(os.path.join(ROOT, filename), "w") as fh:
        fh.write(doc)
    return len(entries)


def write_index(filename, children):
    body = "\n".join(
        f"  <sitemap>\n    <loc>{BASE}/{name}</loc>\n    <lastmod>{mod}</lastmod>\n  </sitemap>"
        for name, mod in children
    )
    doc = (
        '<?xml version="1.0" encoding="UTF-8"?>\n'
        '<sitemapindex xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">\n'
        f"{body}\n"
        "</sitemapindex>\n"
    )
    with open(os.path.join(ROOT, filename), "w") as fh:
        fh.write(doc)


def main():
    en, nl = [], []
    for rel in collect():
        path = url_path(rel)
        entry = (path, lastmod(rel))
        (nl if path.startswith("/nl/") or path == "/nl" else en).append(entry)

    en.sort(key=lambda e: e[0])
    nl.sort(key=lambda e: e[0])

    n_en = write_urlset("sitemap-en.xml", en)
    n_nl = write_urlset("sitemap-nl.xml", nl)

    newest = max(m for _, m in en + nl)
    write_index("sitemap.xml", [("sitemap-en.xml", newest), ("sitemap-nl.xml", newest)])

    print(f"sitemap-en.xml  {n_en} urls")
    print(f"sitemap-nl.xml  {n_nl} urls")
    print(f"sitemap.xml     index -> 2 sitemaps, lastmod {newest}")
    print(f"total           {n_en + n_nl} urls")
    return 0


if __name__ == "__main__":
    sys.exit(main())
