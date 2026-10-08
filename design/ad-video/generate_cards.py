"""Generate the Blanktick ad cards as PNGs (no browser; Pillow only).
Outputs 1080x1920 (9:16): caption overlay (transparent), brand card, CTA card."""
from PIL import Image, ImageDraw, ImageFont

W, H = 1080, 1920
BG = (10, 10, 10)
INK = (255, 255, 255)
MUTED = (180, 180, 180)
FAINT = (138, 138, 138)
ACCENT = (214, 255, 63)
HERE = r"C:\Users\tmant\Projects\blanktick\design\ad-video"
ICON = r"C:\Users\tmant\Projects\blanktick\design\logo\blanktick-icon-512.png"
BOLD = r"C:\Windows\Fonts\arialbd.ttf"
REG = r"C:\Windows\Fonts\arial.ttf"


def font(sz, bold=True):
    return ImageFont.truetype(BOLD if bold else REG, sz)


def wrap(draw, text, fnt, max_w):
    words, lines, cur = text.split(), [], ""
    for w in words:
        t = (cur + " " + w).strip()
        if draw.textlength(t, font=fnt) <= max_w:
            cur = t
        else:
            lines.append(cur); cur = w
    if cur:
        lines.append(cur)
    return lines


def draw_block(draw, lines, fnt, x, y, fill, lh, spacing=0):
    for ln in lines:
        draw.text((x, y), ln, font=fnt, fill=fill)
        y += lh + spacing
    return y


def tick(draw, ox, oy, size, color, wide=None):
    """Draw the broken-tick mark. size = box in px (native 256 space)."""
    s = size / 256.0
    w = wide or max(6, int(30 * s))
    seg1 = [(44, 136), (104, 192), (150, 148)]
    seg2 = [(172, 126), (224, 74)]
    seg1 = [(ox + px * s, oy + py * s) for px, py in seg1]
    seg2 = [(ox + px * s, oy + py * s) for px, py in seg2]
    draw.line(seg1, fill=color, width=w, joint="curve")
    draw.line(seg2, fill=color, width=w)


def load_icon(sz):
    im = Image.open(ICON).convert("RGBA").resize((sz, sz), Image.LANCZOS)
    return im


# ---------- 1. caption overlay (transparent) ----------
ov = Image.new("RGBA", (W, H), (0, 0, 0, 0))
d = ImageDraw.Draw(ov)
# bottom scrim
scrim_top = H - 640
for i, yy in enumerate(range(scrim_top, H)):
    a = int(235 * (i / (H - scrim_top)))
    d.line([(0, yy), (W, yy)], fill=(10, 10, 10, a))
# small mark + wordmark top-left
tick(d, 60, 70, 110, ACCENT)
d.text((190, 92), "blank", font=font(46), fill=MUTED)
wlen = d.textlength("blank", font=font(46))
d.text((190 + wlen, 92), "tick", font=font(46), fill=INK)
# kicker + headline bottom
kf = font(34)
d.text((70, scrim_top + 150), "A W A R N I N G", font=kf, fill=ACCENT)
hf = font(96)
lines = wrap(d, "AI agents are now trained to hack you.", hf, W - 140)
y = scrim_top + 210
for ln in lines:
    # colour the phrase "hack you." faint for emphasis
    if "hack" in ln:
        pre = ln.split("hack")[0]
        d.text((70, y), pre, font=hf, fill=INK)
        d.text((70 + d.textlength(pre, font=hf), y), "hack" + ln.split("hack")[1],
               font=hf, fill=FAINT)
    else:
        d.text((70, y), ln, font=hf, fill=INK)
    y += 104
ov.save(f"{HERE}\\caption-overlay.png")

# ---------- 2. brand card ----------
b = Image.new("RGB", (W, H), BG)
d = ImageDraw.Draw(b)
icon = load_icon(300)
b.paste(icon, ((W - 300) // 2, 300), icon)
d2 = ImageDraw.Draw(b)
# wordmark centred
wf = font(64)
bw = d2.textlength("blank", font=wf); tw = d2.textlength("tick", font=wf)
wx = (W - (bw + tw)) // 2
d2.text((wx, 640), "blank", font=wf, fill=MUTED)
d2.text((wx + bw, 640), "tick", font=wf, fill=INK)
# headline
hf = font(78)
hl = wrap(d2, "The one they can't turn against you.", hf, W - 160)
y = 820
for ln in hl:
    lw = d2.textlength(ln, font=hf)
    d2.text(((W - lw) // 2, y), ln, font=hf, fill=INK)
    y += 90
# promises
pf = font(40, bold=False)
proms = ["No internet permission",
         "Your data never leaves the device",
         "It reports. You decide."]
py = y + 70
for p in proms:
    tick(d2, 160, py - 6, 54, ACCENT, wide=9)
    d2.text((240, py), p, font=pf, fill=INK)
    py += 90
b.save(f"{HERE}\\card-brand.png")

# ---------- 3. CTA card ----------
c = Image.new("RGB", (W, H), BG)
d = ImageDraw.Draw(c)
icon = load_icon(240)
c.paste(icon, ((W - 240) // 2, 470), icon)
hf = font(72)
hl = wrap(d, "Download. Run the check.", hf, W - 160)
y = 800
for ln in hl:
    lw = d.textlength(ln, font=hf)
    d.text(((W - lw) // 2, y), ln, font=hf, fill=INK)
    y += 86
# accent button
bw2, bh2 = 760, 128
bx, by = (W - bw2) // 2, y + 60
d.rectangle([bx, by, bx + bw2, by + bh2], fill=ACCENT)
btf = font(48)
bt = "Download  blanktick"
btw = d.textlength(bt, font=btf)
d.text((bx + (bw2 - btw) // 2, by + (bh2 - 58) // 2), bt, font=btf, fill=BG)
# footer
ff = font(32, bold=False)
foot = "Free. Offline. No internet permission - verify it in 10 seconds."
fl = wrap(d, foot, ff, W - 200)
fy = by + bh2 + 60
for ln in fl:
    lw = d.textlength(ln, font=ff)
    d.text(((W - lw) // 2, fy), ln, font=ff, fill=FAINT)
    fy += 44
c.save(f"{HERE}\\card-cta.png")

print("cards written:", "caption-overlay.png, card-brand.png, card-cta.png")
