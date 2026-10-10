"""Converts a 26x26 zkSNARK portrait to 1-bit for the Flipper's LCD (2x scale)."""
from PIL import Image

ORANGE = (255, 140, 26)
INK = (32, 32, 32)


def luminance(rgb):
    r, g, b = rgb
    return 0.299 * r + 0.587 * g + 0.114 * b


def chroma(rgb):
    return max(rgb) - min(rgb)


def portrait(png_path):
    """26x26 grid of levels: 0 = background/light (off), 1 = mid (dither), 2 = ink.

    - background (pure black) is off; dark tones are ink, mid tones dithered, light off;
    - light pixels on the silhouette's edge become ink, so pale faces keep an outline;
    - small saturated clusters (eyes, studs) are drawn against what surrounds them.
    """
    im = Image.open(png_path).convert("RGB").resize((26, 26), Image.NEAREST)
    px = [[im.getpixel((x, y)) for x in range(26)] for y in range(26)]
    bg = lambda x, y: not (0 <= x < 26 and 0 <= y < 26) or px[y][x] == (0, 0, 0)
    grid = [[0] * 26 for _ in range(26)]
    for y in range(26):
        for x in range(26):
            p = px[y][x]
            if p == (0, 0, 0):
                continue
            l = luminance(p)
            grid[y][x] = 2 if l < 90 else 1 if l < 165 else 0
    # Outline: a light pixel touching the background, inside a solid area (not the
    # glitch trail, whose pixels are mostly surrounded by background).
    for y in range(26):
        for x in range(26):
            if bg(x, y) or grid[y][x] == 2:
                continue
            around = [(x + dx, y + dy) for dx in (-1, 0, 1) for dy in (-1, 0, 1) if dx or dy]
            filled = sum(not bg(a, b) for a, b in around)
            touches = any(bg(x + dx, y + dy) for dx, dy in ((1, 0), (-1, 0), (0, 1), (0, -1)))
            if touches and filled >= 5:
                grid[y][x] = 2
    # Accents: tiny saturated clusters contrast with their neighbourhood.
    accent = lambda x, y: 0 <= x < 26 and 0 <= y < 26 and px[y][x] != (0, 0, 0) and chroma(px[y][x]) > 105
    for y in range(26):
        for x in range(26):
            if not accent(x, y):
                continue
            around = [(x + dx, y + dy) for dx in (-1, 0, 1) for dy in (-1, 0, 1) if dx or dy]
            if sum(accent(a, b) for a, b in around) > 3:
                continue
            others = [grid[b][a] for a, b in around if 0 <= a < 26 and 0 <= b < 26 and not accent(a, b) and not bg(a, b)]
            dark = sum(1 for v in others if v == 2) > len(others) / 2
            grid[y][x] = 0 if dark else 2
    return grid


def draw(canvas, grid, ox, oy, scale=2):
    """canvas: 2D list of bools (True = ink)."""
    for y, row in enumerate(grid):
        for x, level in enumerate(row):
            for dy in range(scale):
                for dx in range(scale):
                    if level == 2 or (level == 1 and (dx + dy) % 2 == 0):
                        canvas[oy + y * scale + dy][ox + x * scale + dx] = True


def preview(canvas, path, scale=4):
    h, w = len(canvas), len(canvas[0])
    im = Image.new("RGB", (w, h), ORANGE)
    for y in range(h):
        for x in range(w):
            if canvas[y][x]:
                im.putpixel((x, y), INK)
    im.resize((w * scale, h * scale), Image.NEAREST).save(path)


if __name__ == "__main__":
    import sys
    canvas = [[False] * 128 for _ in range(64)]
    for k, f in enumerate(sys.argv[2:4]):
        draw(canvas, portrait(f), 6 + k * 64, 6)
    preview(canvas, sys.argv[1])
