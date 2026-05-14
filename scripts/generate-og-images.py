#!/usr/bin/env python3
"""Generate 1200x630 OG images for miiro.app (EN and NL variants).

Run from repo root:
    python3 scripts/generate-og-images.py

Outputs og-image.png and og-image-nl.png in the repo root.
"""
from PIL import Image, ImageDraw, ImageFont
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent

W, H = 1200, 630
PAD = 80

BG = (250, 250, 248)        # --warm  #FAFAF8
DARK = (26, 22, 18)         # --text  #1A1612
SOFT = (119, 119, 119)      # the soft headline color used on the hero
CORAL = (196, 83, 60)       # --coral #C4533C
INDIGO = (74, 92, 232)      # --indigo

HEADLINE_FONT = "/System/Library/Fonts/Supplemental/Georgia Bold.ttf"
HEADLINE_ITALIC = "/System/Library/Fonts/Supplemental/Georgia Bold Italic.ttf"
URL_FONT = "/System/Library/Fonts/Supplemental/Georgia.ttf"

KOI = REPO / "koi-logo.png"


def fit_size(font_path, text, max_width, start_size, min_size=32):
    """Pick the largest font size at which `text` fits within max_width on one line."""
    for size in range(start_size, min_size - 1, -2):
        f = ImageFont.truetype(font_path, size)
        bbox = f.getbbox(text)
        if (bbox[2] - bbox[0]) <= max_width:
            return f, size
    return ImageFont.truetype(font_path, min_size), min_size


def wrap_lines(font, text, max_width, draw):
    """Greedy word wrap. Returns list[str]."""
    words = text.split()
    lines, cur = [], ""
    for w in words:
        trial = (cur + " " + w).strip()
        if draw.textlength(trial, font=font) <= max_width:
            cur = trial
        else:
            if cur:
                lines.append(cur)
            cur = w
    if cur:
        lines.append(cur)
    return lines


def make_image(headline_main, headline_soft, url, out_path):
    img = Image.new("RGB", (W, H), BG)
    draw = ImageDraw.Draw(img)

    # Koi logo top-left, ~96px
    if KOI.exists():
        koi = Image.open(KOI).convert("RGBA")
        koi.thumbnail((96, 96), Image.LANCZOS)
        img.paste(koi, (PAD, PAD), koi)

    # Headline area — fit a serif size that wraps to <=3 lines for the main part.
    max_w = W - PAD * 2
    target = 64
    # Pick a size where main wraps to <=3 lines and soft fits on one line.
    while target >= 44:
        f_main = ImageFont.truetype(HEADLINE_FONT, target)
        main_lines = wrap_lines(f_main, headline_main, max_w, draw)
        f_soft = ImageFont.truetype(HEADLINE_ITALIC, target)
        soft_width = draw.textlength(headline_soft, font=f_soft)
        if len(main_lines) <= 3 and soft_width <= max_w:
            break
        target -= 2

    line_gap = int(target * 1.18)
    total_lines = main_lines + [headline_soft]
    block_h = line_gap * len(total_lines)

    # Vertical placement: anchor block above the URL footer with a comfortable gap.
    y_url = H - PAD - 28
    y_start = y_url - 90 - block_h
    # If too tight (block taller than space), nudge down from the logo.
    if y_start < PAD + 96 + 60:
        y_start = PAD + 96 + 60

    y = y_start
    for line in main_lines:
        draw.text((PAD, y), line, font=f_main, fill=DARK)
        y += line_gap
    draw.text((PAD, y), headline_soft, font=f_soft, fill=SOFT)

    # Coral accent dot + URL bottom-left
    f_url = ImageFont.truetype(URL_FONT, 22)
    dot_r = 6
    cx = PAD + dot_r
    cy = y_url - 4
    draw.ellipse([cx - dot_r, cy - dot_r, cx + dot_r, cy + dot_r], fill=CORAL)
    draw.text((cx + dot_r + 12, y_url - 16), url, font=f_url, fill=DARK)

    img.save(out_path, "PNG", optimize=True)
    return img.size


if __name__ == "__main__":
    en_size = make_image(
        "Tell Sam what your household needs.",
        "It does it.",
        "miiro.app",
        REPO / "og-image.png",
    )
    nl_size = make_image(
        "Vertel Sam wat je huishouden nodig heeft.",
        "Hij regelt het.",
        "miiro.app",
        REPO / "og-image-nl.png",
    )
    print(f"og-image.png    {en_size}")
    print(f"og-image-nl.png {nl_size}")
