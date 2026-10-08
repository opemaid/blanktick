// blanktick_hack_resolve — opaque 720x1280, 8s. Catches the overlay's white
// flash, the air-gap pulse wipes the neon hack to calm cream, the severed tick
// draws, honest line, then the end card. The calm brand resolution.
(function () {
  const MO = window.MO, U = window.U, cl = U.clamp, lerp = U.lerp;
  const PAPER = '#FBFAF6', SKY = '#EEF3EF', INK = '#0B0D0C', MUT = '#5A6260',
        KELP = '#0F4D3F', LIME = '#D6FF3F', SUNK = '#EDEBE4', HAIR = '#DFDBD2';

  function txt(c, s, x, y, px, w, col, align = 'center', track = 0, fam = '"Segoe UI", Arial, sans-serif') {
    c.font = `${w} ${px}px ${fam}`; c.fillStyle = col; c.textBaseline = 'alphabetic';
    let tot = 0; const chs = [...s]; for (const ch of chs) tot += c.measureText(ch).width + track; tot -= track;
    let sx = align === 'center' ? x - tot / 2 : align === 'right' ? x - tot : x;
    for (const ch of chs) { c.fillText(ch, sx, y); sx += c.measureText(ch).width + track; } return tot;
  }
  function tW(c, s, px, w, track = 0, fam = '"Segoe UI", Arial, sans-serif') { c.font = `${w} ${px}px ${fam}`; let t = 0; for (const ch of [...s]) t += c.measureText(ch).width + track; return t - track; }
  function rr(c, x, y, w, h, r) { r = Math.min(r, w / 2, h / 2); c.beginPath(); c.moveTo(x + r, y); c.arcTo(x + w, y, x + w, y + h, r); c.arcTo(x + w, y + h, x, y + h, r); c.arcTo(x, y + h, x, y, r); c.arcTo(x, y, x + w, y, r); c.closePath(); }
  function tick(c, cx, cy, s, drawP, color) {
    c.save(); c.translate(cx, cy); c.scale(s, s); c.translate(-128, -128);
    c.strokeStyle = color; c.lineWidth = 34; c.lineCap = 'butt'; c.lineJoin = 'miter';
    const seg = [[44, 136, 104, 192], [104, 192, 150, 148], [172, 126, 224, 74]];
    const lens = seg.map(a => Math.hypot(a[2] - a[0], a[3] - a[1])), tot = lens.reduce((a, b) => a + b, 0);
    let dn = (drawP == null ? 1 : drawP) * tot;
    for (let i = 0; i < seg.length; i++) { if (dn <= 0) break; const [x0, y0, x1, y1] = seg[i], L = lens[i], f = cl(dn / L);
      c.beginPath(); c.moveTo(x0, y0); c.lineTo(lerp(x0, x1, f), lerp(y0, y1, f)); c.stroke(); dn -= L; }
    c.restore();
  }

  const CLIPS = (window.CLIPS = window.CLIPS || {});
  CLIPS.blanktick_hack_resolve = {
    draw(c, t, ctx) {
      const W = ctx.W, H = ctx.H, cx = W / 2;
      // bg cream (sky gradient)
      const g = c.createLinearGradient(0, 0, 0, H); g.addColorStop(0, PAPER); g.addColorStop(1, SKY);
      c.fillStyle = g; c.fillRect(0, 0, W, H);
      c.fillStyle = 'rgba(15,77,63,0.05)'; for (let x = 0; x < W; x += 60) for (let y = 0; y < H; y += 60) { c.beginPath(); c.arc(x, y, 1.6, 0, 7); c.fill(); }

      const tickCy = H * 0.34;
      // air-gap EMP ring (0.05 -> 0.8)
      if (t < 0.85) { const p = cl(t / 0.8); const r = lerp(20, Math.max(W, H) * 0.9, MO.expoOut(p));
        c.save(); c.globalAlpha = cl(1 - p); c.strokeStyle = LIME; c.lineWidth = lerp(40, 4, p); c.beginPath(); c.arc(cx, tickCy, r, 0, 7); c.stroke();
        c.strokeStyle = KELP; c.lineWidth = lerp(18, 2, p); c.beginPath(); c.arc(cx, tickCy, r * 0.8, 0, 7); c.stroke(); c.restore(); }

      // the tick draws
      const dp = MO.expoOut(cl((t - 0.3) / 1.1));
      tick(c, cx, tickCy, 2.4, dp, KELP);

      // phase 1 lines (1.4 -> 3.4)
      if (t >= 1.3 && t < 3.6) { const a = cl(Math.min((t - 1.3) / 0.3, (3.6 - t) / 0.4, 1));
        c.save(); c.globalAlpha = a;
        txt(c, 'Blanktick shows what’s reaching in.', cx, H * 0.56, 42, 700, INK);
        txt(c, 'It changes nothing without you.', cx, H * 0.61, 30, 500, MUT);
        c.restore();
      }

      // phase 2 end card (3.4 -> 8)
      if (t >= 3.4) {
        const a = cl((t - 3.4) / 0.4);
        c.save(); c.globalAlpha = a;
        txt(c, 'blanktick', cx, H * 0.5, 84, 800, INK, -1);
        const tg = cl((t - 3.8) / 0.4); if (tg > 0) { c.globalAlpha = a * tg; txt(c, 'It shows what others don’t check.', cx, H * 0.55, 30, 500, MUT); }
        const pp = cl((t - 4.1) / 0.5);
        if (pp > 0) { c.globalAlpha = a * pp; const pills = ['Offline', 'Nothing leaves your computer', 'Free & open source'];
          let py = H * 0.62; pills.forEach((p, i) => { const pa = cl((t - 4.1 - i * 0.15) / 0.4); if (pa <= 0) return; c.globalAlpha = a * pa;
            const w = tW(c, p, 28, 600) + 56, x = cx - w / 2;
            c.fillStyle = SUNK; c.strokeStyle = HAIR; c.lineWidth = 2; rr(c, x, py, w, 54, 27); c.fill(); c.stroke();
            c.fillStyle = KELP; c.beginPath(); c.arc(x + 24, py + 27, 4.5, 0, 7); c.fill();
            txt(c, p, x + 34, py + 36, 28, 600, INK, 'left'); py += 68; });
        }
        c.restore();
      }
    }
  };
})();
