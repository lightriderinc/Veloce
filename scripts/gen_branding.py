#!/usr/bin/env python3
"""Render the Veloce brand mark into installer and application assets.

Single source of truth for the mark geometry is assets/branding/veloce.svg
(black disc, Lightrider gradient ring, white V). This script renders the same
geometry with Pillow into the binary formats the platform packagers need:

  assets/branding/veloce.ico        Windows executable, shortcut, and MSI icon
  assets/branding/veloce.icns       macOS application icon
  assets/branding/veloce-256.png    documentation and generic use
  assets/branding/wix-banner.bmp    WixUI top banner (493 x 58)
  assets/branding/wix-dialog.bmp    WixUI welcome and exit dialog (493 x 312)

The outputs are committed so that release hosts do not need Pillow. Rerun
after changing the palette or the mark:

  python3 scripts/gen_branding.py
"""
from __future__ import annotations

from pathlib import Path
from typing import List, Tuple

from PIL import Image, ImageDraw, ImageFont

ROOT = Path(__file__).resolve().parent.parent
OUT = ROOT / "assets" / "branding"

# Lightrider gradient palette, sampled from the brand ring (yellow at the
# upper left, crimson at the lower right).
PALETTE: List[Tuple[float, Tuple[int, int, int]]] = [
    (0.00, (0xFF, 0xF8, 0x02)),
    (0.18, (0xFF, 0xDC, 0x0C)),
    (0.42, (0xFD, 0x8C, 0x27)),
    (0.68, (0xF8, 0x28, 0x48)),
    (1.00, (0xA7, 0x28, 0x48)),
]
DISC = (0, 0, 0)
INK_DARK = (11, 11, 13)
MUTED = (152, 152, 157)
WHITE = (255, 255, 255)
FONT_BOLD = "/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf"
FONT_REGULAR = "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf"


def palette_color(t: float) -> Tuple[int, int, int]:
    t = min(1.0, max(0.0, t))
    for (t0, c0), (t1, c1) in zip(PALETTE, PALETTE[1:]):
        if t <= t1:
            k = 0.0 if t1 == t0 else (t - t0) / (t1 - t0)
            return tuple(round(a + (b - a) * k) for a, b in zip(c0, c1))
    return PALETTE[-1][1]


def gradient_image(width: int, height: int, angle: str = "diagonal") -> Image.Image:
    """135 degree (diagonal) or horizontal Lightrider gradient."""
    image = Image.new("RGB", (width, height))
    pixels = image.load()
    for y in range(height):
        for x in range(width):
            if angle == "horizontal":
                t = x / max(1, width - 1)
            elif angle == "vertical":
                t = y / max(1, height - 1)
            else:
                t = (x + y) / max(1, width + height - 2)
            pixels[x, y] = palette_color(t)
    return image


def render_mark(size: int) -> Image.Image:
    """Render the mark at `size` px with 4x supersampling."""
    scale = 4
    big = size * scale
    unit = big / 48.0
    ring = Image.new("L", (big, big), 0)
    ImageDraw.Draw(ring).ellipse(
        [0, 0, big - 1, big - 1], fill=255)
    gradient = gradient_image(big, big).convert("RGBA")
    mark = Image.new("RGBA", (big, big), (0, 0, 0, 0))
    mark.paste(gradient, (0, 0), ring)
    draw = ImageDraw.Draw(mark)
    inset = 3.5 * unit
    draw.ellipse([inset, inset, big - inset, big - inset], fill=DISC + (255,))
    stroke = int(round(4.5 * unit))
    points = [(15 * unit, 15.5 * unit), (24 * unit, 33.5 * unit),
              (33 * unit, 15.5 * unit)]
    draw.line(points, fill=WHITE + (255,), width=stroke, joint="curve")
    radius = stroke / 2
    for x, y in (points[0], points[2]):
        draw.ellipse([x - radius, y - radius, x + radius, y + radius],
                     fill=WHITE + (255,))
    return mark.resize((size, size), Image.LANCZOS)


def write_icons(master: Image.Image) -> None:
    master.save(OUT / "veloce-256.png")
    sizes = [(16, 16), (24, 24), (32, 32), (48, 48), (64, 64),
             (128, 128), (256, 256)]
    master.save(OUT / "veloce.ico", format="ICO", sizes=sizes)
    master.save(OUT / "veloce.icns", format="ICNS")


def write_wix_banner() -> None:
    width, height = 493, 58
    banner = Image.new("RGB", (width, height), WHITE)
    hairline = gradient_image(width, 2, "horizontal")
    banner.paste(hairline, (0, height - 2))
    mark = render_mark(36)
    banner.paste(mark, (width - 36 - 14, (height - 2 - 36) // 2), mark)
    banner.save(OUT / "wix-banner.bmp", format="BMP")


def write_wix_dialog() -> None:
    width, height = 493, 312
    panel_width = 164
    dialog = Image.new("RGB", (width, height), WHITE)
    draw = ImageDraw.Draw(dialog)
    draw.rectangle([0, 0, panel_width - 1, height - 1], fill=INK_DARK)
    strip = gradient_image(4, height, "vertical")
    dialog.paste(strip, (panel_width - 4, 0))
    mark = render_mark(96)
    dialog.paste(mark, ((panel_width - 4 - 96) // 2, 54), mark)
    title = ImageFont.truetype(FONT_BOLD, 24)
    subtitle = ImageFont.truetype(FONT_REGULAR, 12)
    centre = (panel_width - 4) / 2
    draw.text((centre, 176), "Veloce", font=title, fill=WHITE, anchor="mt")
    draw.text((centre, 212), "Lightrider Inc", font=subtitle, fill=MUTED,
              anchor="mt")
    draw.text((centre, 232), "Post-quantum security", font=subtitle,
              fill=MUTED, anchor="mt")
    dialog.save(OUT / "wix-dialog.bmp", format="BMP")


def main() -> int:
    OUT.mkdir(parents=True, exist_ok=True)
    master = render_mark(1024)
    write_icons(master)
    write_wix_banner()
    write_wix_dialog()
    for name in ("veloce.ico", "veloce.icns", "veloce-256.png",
                 "wix-banner.bmp", "wix-dialog.bmp"):
        print(f"wrote {OUT / name} ({(OUT / name).stat().st_size} bytes)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
