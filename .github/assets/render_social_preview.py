#!/usr/bin/env python3
"""Regenerate .github/assets/social-preview.png (GitHub: 1280x640).

    python3 .github/assets/render_social_preview.py

Requires Pillow; uses the system DejaVu Sans Mono font.
"""
import os

from PIL import Image, ImageDraw, ImageFont

W, H = 1280, 640
BG = (13, 17, 23)          # github dark
PANEL = (22, 27, 34)
BORDER = (48, 54, 61)
FG = (201, 209, 217)
BRIGHT = (230, 237, 243)
DIM = (110, 118, 129)
GREEN = (63, 185, 80)
CYAN = (56, 199, 255)
AMBER = (210, 168, 83)
ACCENT = (88, 166, 255)

FONT = "/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf"
f_body = ImageFont.truetype(FONT, 26)
f_small = ImageFont.truetype(FONT, 22)


def main():
    img = Image.new("RGB", (W, H), BG)
    d = ImageDraw.Draw(img)

    d.rectangle([0, 0, W, 6], fill=ACCENT)

    px, py, pw, ph = 70, 60, W - 140, 330
    d.rounded_rectangle([px, py, px + pw, py + ph], radius=14,
                        fill=PANEL, outline=BORDER, width=2)
    for i, c in enumerate([(255, 95, 86), (255, 189, 46), (39, 201, 63)]):
        d.ellipse([px + 24 + i * 34, py + 22, px + 40 + i * 34, py + 38],
                  fill=c)

    def span(x, y, parts, font=f_body):
        for t, c in parts:
            d.text((x, y), t, font=font, fill=c)
            x += d.textlength(t, font=font)

    ty = py + 64
    span(px + 40, ty, [("┌" + "─" * 56 + "┐", BORDER)])
    ty += 38
    span(px + 40, ty, [("│  ", BORDER), ("smolvault", BRIGHT),
                       (" 0.2.1", DIM)])
    ty += 40
    rows = [
        [("│  ", BORDER), ("vault   ", DIM), ("vault.vault", FG),
         (" · ", DIM), ("12 files", FG), (" · ", DIM),
         ("22.3 GB logical", FG), (" · ", DIM), ("11 GB stored", GREEN)],
        [("│  ", BORDER), ("local   ", DIM),
         ("http://127.0.0.1:8100/", CYAN)],
        [("│  ", BORDER), ("network ", DIM),
         ("http://192.168.1.14:8100/", CYAN), ("   ● running", GREEN),
         ("   ← phone/TV ready", DIM)],
        [("│  ", BORDER), ("auth    ", DIM), ("password protected", FG),
         (" · AES-256-GCM at rest", GREEN)],
    ]
    for row in rows:
        span(px + 40, ty, row)
        ty += 36
    span(px + 40, ty, [("└" + "─" * 56 + "┘", BORDER)])

    hy = py + ph + 34
    span(px, hy, [("immutable", GREEN), ("  · deduplicated", FG),
                  ("  · encrypted at rest", AMBER)], f_body)
    d.text((px, hy + 52),
           "one file · zero dependencies · streams 4K from a Pi-sized RAM "
           "budget", font=f_small, fill=DIM)

    t = "github.com/smolfiddle/smolvault"
    d.text((W - d.textlength(t, font=f_small) - 48, H - 56), t,
           font=f_small, fill=DIM)

    out = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                       "social-preview.png")
    img.save(out, optimize=True)
    print(f"saved {out} ({os.path.getsize(out)} bytes)")


if __name__ == "__main__":
    main()
