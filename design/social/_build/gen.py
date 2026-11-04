"""
Blanktick social banners, in the blanktick.org "paper & kelp" design.

    python gen.py            -> writes *.html here, then render.sh screenshots them

Every format has a SAFE box: the area that survives the platform's crops and
profile-photo overlaps. Copy and the logo go only inside it. The tick matrix is
decoration and is allowed to run under overlaps and off the edges.
"""
from __future__ import annotations
import pathlib

HERE = pathlib.Path(__file__).parent

PAPER, SUNK, INK, INK2, KELP, HAIR = "#FBFAF6", "#EDEBE4", "#17191B", "#3A3F3D", "#0F4D3F", "#DFDBD2"

# 256-grid geometry of the severed tick, from web/favicon.svg.
TICK = '<path d="M44 136 L104 192 L150 148"/><path d="M172 126 L224 74"/>'


def mark(size: int, tile: bool = False) -> str:
    """The logo. tile=True draws it on its paper square, like the app icon."""
    if tile:
        return (f'<svg width="{size}" height="{size}" viewBox="0 0 256 256">'
                f'<rect width="256" height="256" fill="{PAPER}"/>'
                f'<g transform="translate(128 128) scale(0.8) translate(-134 -133)" fill="none" '
                f'stroke="{KELP}" stroke-width="34" stroke-linecap="butt" stroke-linejoin="miter">{TICK}</g></svg>')
    return (f'<svg width="{size}" height="{size * 166 / 228:.0f}" viewBox="20 50 228 166">'
            f'<g fill="none" stroke="{KELP}" stroke-width="34" stroke-linecap="butt" stroke-linejoin="miter">{TICK}</g></svg>')


def cell(filled: bool, s: int) -> str:
    """One receipt cell. Checked = kelp square + paper tick. Not checked = ink
    outline + hollow blank tick, drawn in INK so it is never the quieter one."""
    g = 'transform="translate(128 128) scale(0.62) translate(-134 -133)" fill="none" stroke-linecap="butt" stroke-linejoin="miter"'
    if filled:
        return (f'<svg width="{s}" height="{s}" viewBox="0 0 256 256"><rect width="256" height="256" fill="{KELP}"/>'
                f'<g {g} stroke="{PAPER}" stroke-width="34">{TICK}</g></svg>')
    return (f'<svg width="{s}" height="{s}" viewBox="0 0 256 256">'
            f'<rect x="9" y="9" width="238" height="238" fill="{PAPER}" stroke="{INK}" stroke-width="18"/>'
            f'<g {g} stroke="{INK}" stroke-width="34">{TICK}</g></svg>')


def matrix(cols: int, rows: int, s: int, gap: int, filled: int | None = None) -> str:
    n = cols * rows
    k = round(n * 50 / 81) if filled is None else filled  # same 50:31 ratio as the real scan
    # Column-major fill: checked columns first, then not-checked, so a cropped
    # banner still shows both kinds side by side.
    cells = "".join(cell((c * rows + r) < k, s) for r in range(rows) for c in range(cols))
    return (f'<div class="mx" style="grid-template-columns:repeat({cols},{s}px);gap:{gap}px">{cells}</div>')


CSS = f"""
@font-face{{font-family:H;src:url(hanken-grotesk-var-latin.woff2);font-weight:100 900}}
@font-face{{font-family:M;src:url(ibm-plex-mono-600-latin.woff2);font-weight:600}}
@font-face{{font-family:N;src:url(newsreader-italic-latin.woff2);font-style:italic}}
*{{box-sizing:border-box}}
html,body{{margin:0;overflow:hidden}}
body{{background:{PAPER};color:{INK};font-family:H;position:relative;
  background-image:radial-gradient({HAIR} 1.4px,transparent 1.4px);background-size:var(--dot) var(--dot)}}
.safe{{position:absolute;display:flex;flex-direction:column;justify-content:center}}
.lock{{display:flex;align-items:center;gap:calc(var(--u)*.45)}}
.wm{{font-weight:800;letter-spacing:-.02em;line-height:1;font-size:calc(var(--u)*1.25)}}
.kick{{font-family:M;font-weight:600;text-transform:uppercase;letter-spacing:.16em;color:{KELP};font-size:calc(var(--u)*.3)}}
.h{{font-weight:700;letter-spacing:-.025em;line-height:1.02;font-size:calc(var(--u)*.95)}}
.q{{font-family:N;font-style:italic;font-weight:400;letter-spacing:-.01em}}
.line{{font-weight:600;letter-spacing:-.015em;line-height:1.15;font-size:calc(var(--u)*.62);color:{INK}}}
.line em{{font-family:N;font-weight:400;color:{KELP}}}
.cta{{display:inline-flex;align-self:flex-start;align-items:center;gap:calc(var(--u)*.3);background:{KELP};color:{PAPER};
  font-weight:700;font-size:calc(var(--u)*.5);padding:calc(var(--u)*.28) calc(var(--u)*.5)}}
.sub{{font-family:M;font-weight:600;letter-spacing:.16em;text-transform:uppercase;color:{INK2};font-size:calc(var(--u)*.26)}}
.mx{{display:grid}}
.deco{{position:absolute}}
.rcpt{{display:flex;gap:calc(var(--u)*.9);align-items:flex-end}}
.fig{{font-weight:800;letter-spacing:-.04em;line-height:.9;font-size:calc(var(--u)*1.6);font-variant-numeric:tabular-nums}}
.lbl{{font-family:M;font-weight:600;letter-spacing:.14em;text-transform:uppercase;font-size:calc(var(--u)*.24);margin-top:calc(var(--u)*.15)}}
.rule{{height:2px;background:{INK};opacity:.9}}
"""


def page(w: int, h: int, u: float, dot: int, body: str) -> str:
    return (f'<!doctype html><html><head><meta charset="utf-8"><style>{CSS}'
            f'html,body{{width:{w}px;height:{h}px}} body{{--u:{u}px;--dot:{dot}px}}</style></head>'
            f'<body>{body}</body></html>')


def lockup(u: float) -> str:
    return f'<div class="lock">{mark(int(u * 1.5))}<div class="wm">blanktick</div></div>'


def gap(px: float) -> str:
    return f'<div style="height:{px:.0f}px"></div>'


def receipt(u: float) -> str:
    return (f'<div class="rcpt"><div><div class="fig" style="color:{KELP}">50</div><div class="lbl">Checks ran</div></div>'
            f'<div><div class="fig">31</div><div class="lbl">Could not be checked</div></div></div>')


def headline(u: float, size: float = .95) -> str:
    return (f'<div class="h" style="font-size:{u * size:.0f}px">A green tick can mean<br>'
            f'<span class="q">&ldquo;we checked, it&rsquo;s fine.&rdquo;</span><br>Or it can mean<br>'
            f'<span class="q">&ldquo;we never looked.&rdquo;</span></div>')


ONE_LINE = 'The security scanner that tells you<br><em>what it could not check.</em>'


def wide(w, h, safe, u, dot, copy_w, cell_px, margin=None, show_cta=True, line_size=.62):
    """Banner: copy in the safe box on the left; the tick matrix fills the right,
    vertically centred, at least a gutter clear of the copy, never cropped."""
    x, y, sw, sh = safe
    copy = (f'<div class="safe" style="left:{x}px;top:{y}px;width:{copy_w}px;height:{sh}px">'
            f'{lockup(u)}{gap(u * .45)}<div class="line" style="font-size:{u * line_size:.0f}px">{ONE_LINE}</div>')
    if show_cta:
        copy += f'{gap(u * .45)}<div class="cta">Download free at blanktick.org</div>'
    copy += '</div>'
    g = max(4, cell_px // 6)
    m = margin if margin is not None else max(g * 2, int(h * .08))
    rows = max(1, (h - 2 * m + g) // (cell_px + g))
    mx_h = rows * cell_px + (rows - 1) * g
    # The grid fits INSIDE the banner, right margin = top margin. It used to bleed
    # off the edge, which cropped away exactly the not-checked cells -- the one
    # thing the brand says must never be the quieter half.
    x0 = x + copy_w + int(u * .9)
    cols = max(2, (w - m - x0 + g) // (cell_px + g))
    x0 = w - m - (cols * cell_px + (cols - 1) * g)
    filled = round(rows * cols * 50 / 81)
    deco = (f'<div class="deco" style="left:{x0}px;top:{(h - mx_h) // 2}px">'
            f'{matrix(cols, rows, cell_px, g, filled)}</div>')
    return page(w, h, u, dot, deco + copy)


def stacked(w, h, safe, u, dot, cols, cell_px, story=False):
    """Square / portrait / story: the website hero, top to bottom."""
    x, y, sw, sh = safe
    body = (f'<div class="safe" style="left:{x}px;top:{y}px;width:{sw}px;height:{sh}px;justify-content:space-between">'
            f'<div>{lockup(u)}</div>'
            f'<div><div class="kick">Offline by construction</div>{gap(u * .35)}{headline(u)}</div>'
            f'<div>{matrix(cols, 9 if story else 4 if cols == 9 else 3, cell_px, max(4, cell_px // 6), None)}'
            f'{gap(u * .5)}{receipt(u)}</div>'
            f'<div><div class="cta">Download free at blanktick.org</div>{gap(u * .35)}'
            f'<div class="sub">Free &middot; Open source &middot; Offline &middot; Windows</div></div></div>')
    return page(w, h, u, dot, body)


def og(w, h, u, dot):
    """GitHub social preview / link preview: hero left, full 81-cell receipt right."""
    left = (f'<div class="safe" style="left:{u * 1.1:.0f}px;top:{u * .9:.0f}px;width:{w * .55:.0f}px;height:{h - u * 1.8:.0f}px;justify-content:space-between">'
            f'{lockup(u)}{headline(u, .82)}<div class="cta">Download free at blanktick.org</div></div>')
    cs = int(h * .068)
    right = (f'<div class="deco" style="right:{u * 1.1:.0f}px;top:50%;transform:translateY(-50%)">'
             f'{matrix(9, 9, cs, max(4, cs // 6), 50)}</div>')
    return page(w, h, u, dot, left + right)


def avatar(n):
    return (f'<!doctype html><html><head><style>html,body{{margin:0;width:{n}px;height:{n}px;overflow:hidden}}</style></head>'
            f'<body>{mark(n, tile=True)}</body></html>')


FORMATS = {
    "x-twitter-header-1500x500": wide(1500, 500, (380, 70, 0, 360), 60, 26, 640, 64),
    "linkedin-company-cover-1128x191": wide(1128, 191, (200, 18, 0, 155), 30, 16, 470, 40, margin=22, show_cta=False, line_size=.6),
    "linkedin-personal-cover-1584x396": wide(1584, 396, (470, 40, 0, 316), 48, 22, 560, 56),
    "facebook-cover-1640x624": wide(1640, 624, (300, 90, 0, 444), 62, 26, 660, 66),
    "youtube-channel-art-2560x1440": wide(2560, 1440, (527, 528, 0, 383), 66, 30, 760, 72),
    "reddit-banner-1920x384": wide(1920, 384, (120, 40, 0, 304), 52, 22, 640, 56),
    "discord-banner-960x540": wide(960, 540, (60, 60, 0, 420), 40, 20, 470, 52, line_size=.58),
    "og-github-social-preview-1280x640": og(1280, 640, 58, 24),
    "instagram-post-1080x1080": stacked(1080, 1080, (90, 80, 900, 920), 62, 26, 13, 40),
    "instagram-portrait-1080x1350": stacked(1080, 1350, (90, 90, 900, 1170), 66, 26, 9, 60),
    "instagram-tiktok-story-1080x1920": stacked(1080, 1920, (90, 260, 900, 1400), 70, 28, 9, 62, story=True),
    "avatar-400x400": avatar(400),
    "avatar-1024x1024": avatar(1024),
}

if __name__ == "__main__":
    for name, html in FORMATS.items():
        (HERE / f"{name}.html").write_text(html, encoding="utf-8")
    print(len(FORMATS), "pages written")
