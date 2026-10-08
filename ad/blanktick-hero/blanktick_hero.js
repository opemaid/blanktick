// blanktick_hero — fun cartoon: AI "minions" swarm a PC, the Blanktick tick
// flies in as a superhero and blasts them off with the air-gap shockwave.
// Uses built-in MO (spring/bounce/elastic/wiggle/float/settle) + TOON (glow).
// Dramatized hero metaphor; end card keeps the honest tagline.
(function () {
  const MO = window.MO, TOON = window.TOON, U = window.U;
  const cl = U.clamp, lerp = U.lerp;
  const PAPER = '#FBFAF6', SKY = '#E8F1EC', INK = '#17191B', MUT = '#5A6260',
        KELP = '#0F4D3F', KELPB = '#1E7A5E', LIME = '#D6FF3F', LIMED = '#B6E02F',
        MBODY = '#2C302E', MBELLY = '#3C423F', SCREEN = '#0E1A16', SUNK = '#EDEBE4', HAIR = '#DFDBD2';

  function font(c, px, w = 700, fam = '"Arial Black", "Segoe UI", Arial, sans-serif') { c.font = `${w} ${px}px ${fam}`; }
  function ctext(c, text, x, y, px, w, color, track = 0, align = 'center', fam) {
    font(c, px, w, fam); c.fillStyle = color; c.textBaseline = 'alphabetic';
    let tot = 0; const chs = [...text]; for (const ch of chs) tot += c.measureText(ch).width + track; tot -= track;
    let sx = align === 'center' ? x - tot / 2 : align === 'right' ? x - tot : x;
    for (const ch of chs) { c.fillText(ch, sx, y); sx += c.measureText(ch).width + track; }
    return tot;
  }
  function tW(c, text, px, w, track = 0, fam) { font(c, px, w, fam); let t = 0; for (const ch of [...text]) t += c.measureText(ch).width + track; return t - track; }
  function rr(c, x, y, w, h, r) { r = Math.min(r, w / 2, h / 2); c.beginPath(); c.moveTo(x + r, y); c.arcTo(x + w, y, x + w, y + h, r); c.arcTo(x + w, y + h, x, y + h, r); c.arcTo(x, y + h, x, y, r); c.arcTo(x, y, x + w, y, r); c.closePath(); }

  // severed-tick mark in a 256 box; drawP draws it on; returns nothing.
  function tickMark(c, cx, cy, s, drawP, color, lw) {
    c.save(); c.translate(cx, cy); c.scale(s, s); c.translate(-128, -128);
    c.strokeStyle = color; c.lineWidth = lw || 34; c.lineCap = 'butt'; c.lineJoin = 'miter';
    const seg = [[44, 136, 104, 192], [104, 192, 150, 148], [172, 126, 224, 74]];
    const lens = seg.map(a => Math.hypot(a[2] - a[0], a[3] - a[1])); const tot = lens.reduce((a, b) => a + b, 0);
    let dn = (drawP == null ? 1 : drawP) * tot;
    for (let i = 0; i < seg.length; i++) { if (dn <= 0) break; const [x0, y0, x1, y1] = seg[i], L = lens[i], f = cl(dn / L);
      c.beginPath(); c.moveTo(x0, y0); c.lineTo(lerp(x0, x1, f), lerp(y0, y1, f)); c.stroke(); dn -= L; }
    c.restore();
  }

  // a cute-menacing minion. t for idle, look toward (lx,ly), squash, spin, alpha, dazed.
  function minion(c, x, y, s, t, lx, ly, squash, alpha, spin, dazed, ph) {
    c.save(); c.globalAlpha *= alpha; c.translate(x, y); c.rotate(spin || 0);
    c.scale(1 / Math.sqrt(squash), squash);
    c.lineJoin = 'round'; c.lineCap = 'round'; c.strokeStyle = INK; c.lineWidth = Math.max(4, s * 0.1);
    const R = s;
    // legs
    const lw = Math.max(5, s * 0.14);
    c.strokeStyle = INK; c.lineWidth = lw; c.lineCap = 'round';
    for (const sx of [-1, 1]) { const sw = Math.sin(t * 9 + (sx > 0 ? 1 : 0) + ph) * R * 0.12;
      c.beginPath(); c.moveTo(sx * R * 0.4, R * 0.82); c.quadraticCurveTo(sx * R * 0.5, R * 1.05, sx * R * 0.38 + sw, R * 1.22); c.stroke();
      c.fillStyle = INK; c.beginPath(); c.ellipse(sx * R * 0.38 + sw, R * 1.26, R * 0.14, R * 0.08, 0, 0, 7); c.fill(); }
    // arms (rubber hose, waving)
    for (const sx of [-1, 1]) { const wv = Math.sin(t * 7 + (sx > 0 ? 2.1 : 0) + ph) * R * 0.5 - R * 0.2;
      c.strokeStyle = INK; c.lineWidth = lw; c.beginPath(); c.moveTo(sx * R * 0.78, R * 0.05);
      c.quadraticCurveTo(sx * R * 1.15, wv, sx * R * 1.2, wv - R * 0.25); c.stroke();
      c.fillStyle = '#FAFAF6'; c.beginPath(); c.arc(sx * R * 1.2, wv - R * 0.25, R * 0.17, 0, 7); c.fill(); c.stroke(); }
    // body
    c.fillStyle = MBODY; rr(c, -R * 0.82, -R * 0.95, R * 1.64, R * 1.9, R * 0.62); c.fill(); c.stroke();
    c.fillStyle = MBELLY; c.beginPath(); c.ellipse(0, R * 0.35, R * 0.52, R * 0.5, 0, 0, 7); c.fill();
    // goggle band (lime)
    c.fillStyle = LIME; rr(c, -R * 0.86, -R * 0.4, R * 1.72, R * 0.5, R * 0.1); c.fill(); c.strokeStyle = INK; c.lineWidth = Math.max(3, s * 0.06); rr(c, -R * 0.86, -R * 0.4, R * 1.72, R * 0.5, R * 0.1); c.stroke();
    // eyes
    const ex = cl((lx - x) / 600, -1, 1), ey = cl((ly - y) / 400, -1, 1);
    for (const sx of [-1, 1]) {
      const gx = sx * R * 0.4, gy = -R * 0.15, gr = R * 0.3;
      c.fillStyle = '#fff'; c.beginPath(); c.arc(gx, gy, gr, 0, 7); c.fill(); c.strokeStyle = INK; c.lineWidth = Math.max(3, s * 0.05); c.stroke();
      if (dazed) { c.strokeStyle = INK; c.lineWidth = Math.max(3, s * 0.06); // swirl
        c.beginPath(); for (let a = 0; a < 9; a += 0.3) { const rr2 = gr * 0.85 * (1 - a / 12); const px = gx + Math.cos(a + t * 4) * rr2, py = gy + Math.sin(a + t * 4) * rr2; a === 0 ? c.moveTo(px, py) : c.lineTo(px, py); } c.stroke();
      } else { c.fillStyle = INK; c.beginPath(); c.arc(gx + ex * gr * 0.4, gy + ey * gr * 0.4, gr * 0.42, 0, 7); c.fill();
        c.fillStyle = '#fff'; c.beginPath(); c.arc(gx + ex * gr * 0.4 - gr * 0.14, gy + ey * gr * 0.4 - gr * 0.16, gr * 0.14, 0, 7); c.fill(); }
    }
    // mouth: grin (attacking) or o (dazed)
    c.strokeStyle = INK; c.lineWidth = Math.max(4, s * 0.08); c.fillStyle = '#5A1E26';
    if (dazed) { c.beginPath(); c.ellipse(0, R * 0.5, R * 0.14, R * 0.12, 0, 0, 7); c.fill(); c.stroke(); }
    else { c.beginPath(); c.moveTo(-R * 0.26, R * 0.42); c.quadraticCurveTo(0, R * 0.72, R * 0.26, R * 0.42);
      c.lineTo(R * 0.2, R * 0.5); c.quadraticCurveTo(0, R * 0.64, -R * 0.2, R * 0.5); c.closePath(); c.fillStyle = '#6E2430'; c.fill(); c.stroke();
      // little fangs
      c.fillStyle = '#fff'; for (const fx of [-0.12, 0.12]) { c.beginPath(); c.moveTo(fx * R - R * 0.03, R * 0.44); c.lineTo(fx * R + R * 0.03, R * 0.44); c.lineTo(fx * R, R * 0.52); c.closePath(); c.fill(); } }
    if (dazed) { // stun stars
      c.globalAlpha *= 1; for (let k = 0; k < 3; k++) { const a = t * 5 + k * 2.1; const sx = Math.cos(a) * R * 0.9, sy = -R * 1.25 + Math.sin(a) * R * 0.25; star(c, sx, sy, R * 0.18, LIMED); }
    }
    c.restore();
  }

  function star(c, x, y, r, col) { c.save(); c.translate(x, y); c.fillStyle = col; c.strokeStyle = INK; c.lineWidth = Math.max(2, r * 0.18); c.beginPath();
    for (let i = 0; i < 10; i++) { const a = -Math.PI / 2 + i * Math.PI / 5, rr2 = i % 2 ? r * 0.45 : r; const px = Math.cos(a) * rr2, py = Math.sin(a) * rr2; i === 0 ? c.moveTo(px, py) : c.lineTo(px, py); } c.closePath(); c.fill(); c.stroke(); c.restore(); }

  function laptop(c, cx, cy, s, happy, shake) {
    c.save(); c.translate(cx + (shake || 0), cy); c.scale(s, s);
    const w = 380, h = 250, r = 18;
    c.lineWidth = 8; c.strokeStyle = INK; c.fillStyle = SCREEN; rr(c, -w / 2, -h / 2, w, h, r); c.fill(); c.stroke();
    // face on screen
    const ey = -10, er = 26;
    c.fillStyle = '#EAF1EE';
    for (const sx of [-1, 1]) { c.beginPath(); c.arc(sx * 70, ey, er, 0, 7); c.fill(); c.fillStyle = INK;
      const look = happy ? 0 : 6; c.beginPath(); c.arc(sx * 70 + (happy ? 0 : 0), ey + (happy ? -4 : 8), happy ? 12 : 10, 0, 7); c.fill(); c.fillStyle = '#EAF1EE'; }
    // mouth
    c.strokeStyle = '#EAF1EE'; c.lineWidth = 9; c.lineCap = 'round'; c.beginPath();
    if (happy) { c.arc(0, 40, 46, 0.15 * Math.PI, 0.85 * Math.PI); }
    else { c.arc(0, 86, 42, 1.15 * Math.PI, 1.85 * Math.PI); }   // frown
    c.stroke();
    // base
    c.fillStyle = INK; c.beginPath(); c.moveTo(-w / 2 - 40, h / 2 + 42); c.lineTo(w / 2 + 40, h / 2 + 42); c.lineTo(w / 2 - 8, h / 2 + 6); c.lineTo(-w / 2 + 8, h / 2 + 6); c.closePath(); c.fill();
    c.restore();
  }

  // the hero tick with a flowing cape + aura.
  function hero(c, cx, cy, s, t, squash, capeSwing) {
    c.save(); c.translate(cx, cy); c.scale(1 / Math.sqrt(squash), squash); c.translate(-cx, -cy);
    // comic sunburst rays behind the tick = heroic reveal (reads cleaner than a cape on a flat icon)
    c.save(); c.translate(cx, cy); c.rotate(t * 0.5);
    const R0 = 72 * s, R1 = 168 * s, n = 16; c.fillStyle = 'rgba(214,255,63,0.55)';
    for (let i = 0; i < n; i++) { const a = i * 2 * Math.PI / n, w = 0.085;
      c.beginPath(); c.moveTo(Math.cos(a - w) * R0, Math.sin(a - w) * R0); c.lineTo(Math.cos(a) * R1, Math.sin(a) * R1); c.lineTo(Math.cos(a + w) * R0, Math.sin(a + w) * R0); c.closePath(); c.fill(); }
    c.restore();
    // soft aura, reduced so the tick stays the focal point
    if (TOON && TOON.glow) TOON.glow(c, cx, cy, 118 * s, LIME, 0.16);
    // tick with a cream keyline so it separates from the rays
    tickMark(c, cx, cy, 2.0 * s, 1, '#FBFAF6', 50);
    tickMark(c, cx, cy, 2.0 * s, 1, KELP, 34);
    c.restore();
  }

  const CLIPS = (window.CLIPS = window.CLIPS || {});
  CLIPS.blanktick_hero = {
    draw(c, t, ctx) {
      const W = ctx.W, H = ctx.H, cx = W / 2, cy = H * 0.54;
      // bg gradient sky + soft dots
      const g = c.createLinearGradient(0, 0, 0, H); g.addColorStop(0, PAPER); g.addColorStop(1, SKY);
      c.fillStyle = g; c.fillRect(0, 0, W, H);
      c.fillStyle = 'rgba(15,77,63,0.05)'; const gs = 70, ox = (t * 8) % gs;
      for (let x = -gs + ox; x < W + gs; x += gs) for (let y = -gs; y < H + gs; y += gs) { c.beginPath(); c.arc(x, y, 2, 0, 7); c.fill(); }

      const POW = 7.0;
      const saved = t >= POW;

      // ---- laptop (enters 2.0, shakes while attacked, happy after save) ----
      if (t >= 1.9) {
        const inp = MO.backOut(cl((t - 1.9) / 0.6));
        const shake = (!saved && t > 2.8) ? Math.sin(t * 40) * 4 : 0;
        const sc = lerp(0.3, 1, inp);
        laptop(c, cx, cy, sc, saved, shake);
        if (saved) { // small "protected" badge in the laptop's corner
          const bp = MO.bouncy(cl((t - POW - 0.15) / 0.6));
          if (bp > 0) { c.save(); c.globalAlpha = cl(bp); tickMark(c, cx + 128, cy + 58, 0.4 * bp, 1, KELPB, 30); c.restore(); }
        }
      }

      // ---- minions ----
      const mins = [
        { bx: W * 0.16, by: H * 0.30, at: 2.6, ph: 0, dir: -1 },
        { bx: W * 0.84, by: H * 0.28, at: 2.9, ph: 1.2, dir: 1 },
        { bx: W * 0.12, by: H * 0.76, at: 3.2, ph: 2.1, dir: -1 },
        { bx: W * 0.86, by: H * 0.74, at: 3.5, ph: 0.6, dir: 1 },
        { bx: W * 0.5, by: H * 0.2, at: 3.0, ph: 1.7, dir: 1 }
      ];
      mins.forEach((m, i) => {
        if (t < m.at) return;
        const inp = MO.bouncy(cl((t - m.at) / 0.5));
        // attacking: creep toward laptop a bit
        const creep = saved ? 0 : cl((t - m.at) / 3) * 0.12;
        let x = lerp(m.bx, cx, creep), y = lerp(m.by, cy, creep), s = 56, alpha = 1, spin = 0, squash = 1, dazed = false;
        if (!saved) { y += Math.sin(t * 4 + m.ph) * 10; squash = 1 + 0.06 * Math.sin(t * 8 + m.ph); s *= inp; }
        else {
          const lt = t - POW;
          if (i < 3) { // blasted off-screen, spinning
            const dx = (m.bx < cx ? -1 : 1), dy = (m.by < cy ? -1 : 1);
            x = lerp(x, x + dx * 900, MO.expoOut(cl(lt / 0.9)));
            y = lerp(y, y + dy * 500 - 200, MO.expoOut(cl(lt / 0.9)));
            spin = lt * 12 * dx; alpha = cl(1 - lt / 1.0);
          } else { // two linger, dazed, then leave
            dazed = true; alpha = cl(1 - (t - 10.5) / 1.0);
            x = m.bx; y = m.by + Math.sin(t * 2) * 6;
          }
        }
        if (alpha <= 0) return;
        minion(c, x, y, s, t, cx, cy, squash, alpha, spin, dazed, m.ph);
        // "!" over attacking minions, pulsing
        if (!saved && t > m.at + 0.6) { const pp = 0.6 + 0.4 * Math.abs(Math.sin(t * 6 + m.ph));
          ctext(c, '!', x, y - s * 1.7, 54 * pp + 20, 900, '#17191B'); }
      });

      // ---- hero entry + shockwave ----
      if (t >= 6.2) {
        const fly = MO.expoIn(cl((t - 6.2) / 0.8));          // flies in top-left -> stand spot
        const hx = lerp(W * 0.12, cx, fly), hy = lerp(H * 0.08, cy - 178, fly);
        const lt = t - POW;
        let squash = 1, hxx = cx, hyy = cy;
        if (!saved) { // in flight: motion streak
          c.save(); c.globalAlpha = 0.5; c.strokeStyle = LIME; c.lineWidth = 10; c.lineCap = 'round';
          c.beginPath(); c.moveTo(W * 0.12, H * 0.08); c.lineTo(hx, hy); c.stroke(); c.restore();
          hero(c, hx, hy, 0.9, t, 1, 0);
        } else {
          squash = 1 + MO.settle(lt, -0.28, 3.2, 7);          // landing squash + bounce
          // stand above the laptop so its happy, protected face stays visible
          hero(c, cx, cy - 178, 0.66, t, cl(squash, 0.5, 1.6), Math.sin(t * 2.5) * 0.4);
        }
      }
      // shockwave ring at POW
      if (t >= POW && t < POW + 0.7) {
        const p = (t - POW) / 0.7; const rr2 = lerp(40, Math.max(W, H) * 0.65, MO.expoOut(p));
        c.save(); c.globalAlpha = cl(1 - p); c.strokeStyle = LIME; c.lineWidth = lerp(34, 4, p);
        c.beginPath(); c.arc(cx, cy, rr2, 0, 7); c.stroke();
        c.strokeStyle = KELPB; c.lineWidth = lerp(16, 2, p); c.beginPath(); c.arc(cx, cy, rr2 * 0.82, 0, 7); c.stroke();
        c.restore();
      }
      // POW! comic burst
      if (t >= POW && t < POW + 0.6) {
        const p = (t - POW) / 0.6, sc = MO.backOut(cl(p / 0.4)) * (1 - cl((p - 0.6) / 0.4));
        c.save(); c.translate(cx, cy - 20); c.scale(sc, sc); c.rotate(-0.12);
        c.fillStyle = LIME; c.strokeStyle = INK; c.lineWidth = 7;
        c.beginPath(); for (let i = 0; i < 24; i++) { const a = i * Math.PI / 12, rr2 = i % 2 ? 90 : 150; const px = Math.cos(a) * rr2, py = Math.sin(a) * rr2; i === 0 ? c.moveTo(px, py) : c.lineTo(px, py); } c.closePath(); c.fill(); c.stroke();
        ctext(c, 'POW!', 0, 22, 78, 900, KELP); c.restore();
      }

      // ---- titles ----
      if (t < 2.7) { // S1 attack title
        const a = cl(Math.min((t + 0.3) / 0.4, (2.7 - t) / 0.4, 1));
        c.save(); c.globalAlpha = a;
        const pop = MO.backOut(cl(t / 0.6));
        c.save(); c.translate(cx, H * 0.2); c.scale(lerp(0.6, 1, pop), lerp(0.6, 1, pop));
        ctext(c, 'YOUR PC IS UNDER ATTACK!', 0, 0, 72, 900, INK); c.restore();
        c.restore();
      }
      if (t >= 7.4 && t < 12.4) { // save line
        const a = cl(Math.min((t - 7.4) / 0.4, (12.4 - t) / 0.4, 1));
        const pop = MO.backOut(cl((t - 7.4) / 0.6));
        c.save(); c.globalAlpha = a; c.translate(cx, H * 0.88); c.scale(lerp(0.7, 1, pop), lerp(0.7, 1, pop));
        ctext(c, 'Blanktick has your back.', 0, 0, 64, 900, KELP);
        c.restore();
      }

      // ---- end card (12.5 -> 16) ----
      if (t >= 12.5) {
        const a = cl((t - 12.5) / 0.5);
        c.save(); c.globalAlpha = a; c.fillStyle = PAPER; c.fillRect(0, 0, W, H);
        c.fillStyle = 'rgba(15,77,63,0.05)'; for (let x = 0; x < W; x += 70) for (let y = 0; y < H; y += 70) { c.beginPath(); c.arc(x, y, 2, 0, 7); c.fill(); }
        const mp = MO.backOut(cl((t - 12.7) / 0.7)); tickMark(c, cx, H * 0.34, 1.7 * cl(mp, 0.01, 1), 1, KELP);
        const wm = cl((t - 13.1) / 0.5); if (wm > 0) { c.globalAlpha = a * wm; ctext(c, 'blanktick', cx, H * 0.52, 96, 800, INK, -1, 'center', '"Segoe UI", Arial, sans-serif'); }
        const tg = cl((t - 13.4) / 0.5); if (tg > 0) { c.globalAlpha = a * tg; ctext(c, 'It shows what others don’t check.', cx, H * 0.6, 36, 500, MUT, 0, 'center', '"Segoe UI", Arial, sans-serif'); }
        const pp = cl((t - 13.7) / 0.5);
        if (pp > 0) { c.globalAlpha = a * pp; const pills = ['Offline', 'Nothing leaves your computer', 'Free & open source'];
          const padx = 26, gap = 20; const ws = pills.map(p => tW(c, p, 26, 600, 0, '"Segoe UI", Arial, sans-serif') + padx * 2);
          let tot = ws.reduce((x, y) => x + y, 0) + gap * 2, px = cx - tot / 2, py = H * 0.68;
          pills.forEach((p, i) => { c.fillStyle = SUNK; c.strokeStyle = HAIR; c.lineWidth = 2; rr(c, px, py, ws[i], 48, 24); c.fill(); c.stroke();
            c.fillStyle = KELP; c.beginPath(); c.arc(px + padx - 6, py + 24, 4, 0, 7); c.fill();
            ctext(c, p, px + padx + 6, py + 32, 26, 600, INK, 0, 'left', '"Segoe UI", Arial, sans-serif'); px += ws[i] + gap; });
        }
        c.restore();
      }
    }
  };
})();
