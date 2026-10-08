// blanktick_defend — AI agents reach for a PC; the Blanktick severed-tick (the
// air gap) cuts their reach and names them. Self-contained: raw canvas 2D +
// ctx timing helpers only. Brand: cream paper, kelp green, ink. No red/neon/
// navy/purple, no "blocks malware"/"real-time" claims — it SHOWS, it doesn't block.
(function () {
  const PAPER = '#FAF9F6', SUNK = '#EDEBE4', INK = '#0B0D0C', MUT = '#5A6260',
        FAINT = '#8A908D', HAIR = '#DFDBD2', KELP = '#0F4D3F', KELPB = '#2BB673',
        SCREEN = '#0E1A16', GRAPH = '#17191B';

  const cl = (x, a = 0, b = 1) => Math.max(a, Math.min(b, x));
  const lerp = (a, b, p) => a + (b - a) * p;
  const eo = p => 1 - Math.pow(1 - cl(p), 3);
  const eo5 = p => 1 - Math.pow(1 - cl(p), 5);
  const ei = p => Math.pow(cl(p), 2.6);
  const io = p => (p = cl(p)) < .5 ? 4 * p * p * p : 1 - Math.pow(-2 * p + 2, 3) / 2;
  const back = (p, s = 1.7) => { p = cl(p); return 1 + (s + 1) * Math.pow(p - 1, 3) + s * Math.pow(p - 1, 2); };
  const spring = (p, f = 2.2, d = 9) => { p = cl(p); return 1 - Math.exp(-d * p) * Math.cos(2 * Math.PI * f * p); };
  // fade envelope: 0 before start, ramps in, 1, ramps out, 0 after end
  const env = (t, s, e, fi = 0.45, fo = 0.45) => cl(Math.min((t - s) / fi, (e - t) / fo, 1));

  function font(c, px, w = 700, fam = '"Segoe UI", Inter, Arial, sans-serif') { c.font = `${w} ${px}px ${fam}`; }
  function tracked(c, text, x, y, px, w, color, track = 0, align = 'left') {
    font(c, px, w); c.fillStyle = color; c.textBaseline = 'alphabetic';
    let tot = 0; const chs = [...text];
    for (const ch of chs) tot += c.measureText(ch).width + track;
    tot -= track;
    let sx = align === 'center' ? x - tot / 2 : align === 'right' ? x - tot : x;
    for (const ch of chs) { c.fillText(ch, sx, y); sx += c.measureText(ch).width + track; }
    return tot;
  }
  function textW(c, text, px, w, track = 0) { font(c, px, w); let t = 0; for (const ch of [...text]) t += c.measureText(ch).width + track; return t - track; }

  // dot grid, slow drift
  function grid(c, W, H, t) {
    const g = 66, r = 1.6, ox = (t * 7) % g, oy = (t * 5) % g;
    c.fillStyle = 'rgba(11,13,12,0.05)';
    for (let x = -g + ox; x < W + g; x += g) for (let y = -g + oy; y < H + g; y += g) { c.beginPath(); c.arc(x, y, r, 0, 7); c.fill(); }
  }

  // the laptop ("your computer")
  function laptop(c, cx, cy, s, tint = SCREEN) {
    c.save(); c.translate(cx, cy);
    const w = 360 * s, h = 232 * s, r = 16 * s;
    // screen body
    c.lineWidth = 7 * s; c.strokeStyle = INK; c.fillStyle = tint;
    rr(c, -w / 2, -h / 2, w, h, r); c.fill(); c.stroke();
    // little window chrome
    c.fillStyle = 'rgba(95,191,163,0.55)';
    for (let i = 0; i < 3; i++) { c.beginPath(); c.arc(-w / 2 + 26 * s + i * 22 * s, -h / 2 + 24 * s, 5 * s, 0, 7); c.fill(); }
    // two faint content lines
    c.strokeStyle = 'rgba(234,241,238,0.22)'; c.lineWidth = 6 * s; c.lineCap = 'round';
    line(c, -w / 2 + 28 * s, 8 * s, w / 2 - 120 * s, 8 * s);
    line(c, -w / 2 + 28 * s, 40 * s, w / 2 - 60 * s, 40 * s);
    // base
    c.fillStyle = INK; c.strokeStyle = INK; c.lineWidth = 7 * s; c.lineJoin = 'round';
    c.beginPath(); c.moveTo(-w / 2 - 36 * s, h / 2 + 40 * s); c.lineTo(w / 2 + 36 * s, h / 2 + 40 * s);
    c.lineTo(w / 2 - 6 * s, h / 2 + 6 * s); c.lineTo(-w / 2 + 6 * s, h / 2 + 6 * s); c.closePath(); c.fill();
    c.restore();
  }

  // a dark AI agent bot. menace via graphite + single cold eye, not red.
  function agent(c, x, y, s, alpha, dead = false, phase = 0) {
    c.save(); c.globalAlpha *= alpha; c.translate(x, y);
    const body = dead ? '#9A9E9C' : GRAPH, eye = dead ? '#C9CDCB' : KELPB;
    const hw = 46 * s, hh = 40 * s, r = 12 * s;
    // antenna
    c.strokeStyle = body; c.lineWidth = 5 * s; c.lineCap = 'round';
    line(c, 0, -hh - 16 * s, 0, -hh); c.fillStyle = body; c.beginPath(); c.arc(0, -hh - 20 * s, 5 * s, 0, 7); c.fill();
    // head
    c.fillStyle = body; rr(c, -hw, -hh, hw * 2, hh * 2, r); c.fill();
    // eye (scanning) — a slit that drifts unless dead
    const ex = dead ? 0 : Math.sin(phase) * 10 * s;
    c.fillStyle = eye; rr(c, -18 * s + ex, -8 * s, 36 * s, 16 * s, 8 * s); c.fill();
    // legs
    c.strokeStyle = body; c.lineWidth = 5 * s;
    line(c, -20 * s, hh, -30 * s, hh + 20 * s); line(c, 20 * s, hh, 30 * s, hh + 20 * s);
    c.restore();
  }

  // the Blanktick mark (severed tick) in a 256 box, scaled. drawP 0..1 draws it on.
  // returns the gap seam x in canvas space.
  function mark(c, cx, cy, s, drawP, color = KELP) {
    c.save(); c.translate(cx, cy); c.scale(s, s); c.translate(-128, -128);
    c.strokeStyle = color; c.lineWidth = 30; c.lineCap = 'butt'; c.lineJoin = 'miter';
    // tick: 44,136 -> 104,192 -> 150,148  (two segments, length-param draw)
    const seg = [[44, 136, 104, 192], [104, 192, 150, 148], [172, 126, 224, 74]];
    const lens = seg.map(a => Math.hypot(a[2] - a[0], a[3] - a[1]));
    const tot = lens.reduce((a, b) => a + b, 0);
    let drawn = drawP * tot;
    for (let i = 0; i < seg.length; i++) {
      if (drawn <= 0) break;
      const [x0, y0, x1, y1] = seg[i]; const L = lens[i]; const f = cl(drawn / L);
      c.beginPath(); c.moveTo(x0, y0); c.lineTo(lerp(x0, x1, f), lerp(y0, y1, f)); c.stroke();
      drawn -= L;
    }
    c.restore();
    // gap seam x: midpoint between tick end (150,148) and severed start (172,126)
    return cx + (161 - 128) * s;
  }

  function rr(c, x, y, w, h, r) { r = Math.min(r, w / 2, h / 2); c.beginPath(); c.moveTo(x + r, y); c.arcTo(x + w, y, x + w, y + h, r); c.arcTo(x + w, y + h, x, y + h, r); c.arcTo(x, y + h, x, y, r); c.arcTo(x, y, x + w, y, r); c.closePath(); }
  function line(c, x0, y0, x1, y1) { c.beginPath(); c.moveTo(x0, y0); c.lineTo(x1, y1); c.stroke(); }

  // dashed reaching line from (x0,y0) to (x1,y1), progress grows the dash; clipX
  // (if set) truncates the line at that x (the air gap).
  function reach(c, x0, y0, x1, y1, grow, alpha, clipX) {
    c.save(); c.globalAlpha *= alpha;
    let ex = lerp(x0, x1, grow), ey = lerp(y0, y1, grow);
    if (clipX != null && ((x0 < clipX) !== (ex < clipX))) {
      const f = (clipX - x0) / (ex - x0); ex = clipX; ey = lerp(y0, ey, f);
    }
    c.strokeStyle = 'rgba(90,98,96,0.75)'; c.lineWidth = 3; c.setLineDash([10, 9]); c.lineCap = 'butt';
    c.beginPath(); c.moveTo(x0, y0); c.lineTo(ex, ey); c.stroke();
    c.setLineDash([]);
    // arrow/spark head
    c.fillStyle = 'rgba(90,98,96,0.9)'; c.beginPath(); c.arc(ex, ey, 4, 0, 7); c.fill();
    c.restore();
  }

  const CLIPS = (window.CLIPS = window.CLIPS || {});
  CLIPS.blanktick_defend = {
    draw(c, t, ctx) {
      const W = ctx.W, H = ctx.H;
      // background
      c.fillStyle = PAPER; c.fillRect(0, 0, W, H);
      grid(c, W, H, t);
      // gentle camera breathe
      const bx = Math.sin(t / 7 * 2 * Math.PI) * 5, by = Math.cos(t / 2.7 * 2 * Math.PI) * 4;
      c.save(); c.translate(bx, by);

      const cx = W / 2, cy = H * 0.52;
      const agents = [
        { ax: W * 0.14, ay: H * 0.24, at: 1.1 }, { ax: W * 0.86, ay: H * 0.22, at: 1.5 },
        { ax: W * 0.12, ay: H * 0.76, at: 1.9 }, { ax: W * 0.88, ay: H * 0.74, at: 2.3 }
      ];

      // ---- scene envelopes
      const a1 = env(t, -0.5, 4.9, 0.4, 0.5), a2 = env(t, 4.5, 9.9, 0.5, 0.5),
            a3 = env(t, 9.5, 14.4, 0.5, 0.5), a4 = env(t, 14.0, 18.2, 0.5, 0.0);

      // ===== SCENE 1 — the new way in =====
      if (a1 > 0) {
        c.save(); c.globalAlpha = a1;
        laptop(c, cx, cy, 1.0);
        agents.forEach((g, i) => {
          const ap = eo(ctx.p(t, g.at, 0.7)); if (ap <= 0) return;
          const gx = lerp(g.ax + (g.ax < cx ? -80 : 80), g.ax, ap), gy = g.ay;
          const grow = eo(ctx.p(t, g.at + 0.5, 1.2));
          reach(c, gx, gy, cx, cy, grow * 0.78, ap);
          agent(c, gx, gy, 1.0, ap, false, t * 3 + i);
        });
        tracked(c, 'AI AGENTS — A NEW WAY IN', W * 0.5, H * 0.1 + 0, 30, 700, FAINT, 6, 'center');
        const cap = eo(ctx.p(t, 2.6, 0.8));
        if (cap > 0) { c.globalAlpha = a1 * cap;
          tracked(c, 'An AI assistant can already run commands on your PC.', W * 0.5, H * 0.9, 46, 600, INK, 0, 'center'); }
        c.restore();
      }

      // ===== SCENE 2 — the air gap cuts the reach =====
      if (a2 > 0) {
        c.save(); c.globalAlpha = a2;
        laptop(c, cx, cy, 1.0);
        const drawP = eo5(ctx.p(t, 5.0, 1.6));
        const sev = cl((t - 6.2) / 0.7);          // severance progress
        const seam = mark(c, cx, cy - 28, 2.7, drawP);
        // air-gap seam glows as the arm completes
        if (drawP > 0.6) { c.save(); c.globalAlpha = a2 * cl((drawP - 0.6) / 0.4);
          c.strokeStyle = 'rgba(43,182,115,0.5)'; c.lineWidth = 3; c.setLineDash([6, 8]);
          line(c, seam, cy - 150, seam, cy + 150); c.setLineDash([]); c.restore(); }
        agents.forEach((g, i) => {
          const dead = sev > 0.15;
          const grow = lerp(0.8, 0.08, eo(sev));   // the reach retracts as the air gap opens
          reach(c, g.ax, g.ay, cx, cy, grow, 1);
          agent(c, g.ax, g.ay, 1.0, 1, dead, t * 2 + i);
        });
        const w1 = eo(ctx.p(t, 7.4, 0.7));
        if (w1 > 0) { c.globalAlpha = a2 * w1;
          tracked(c, 'The arm is severed. That gap is the air gap.', W * 0.5, H * 0.9, 44, 600, INK, 0, 'center'); }
        c.restore();
      }

      // ===== SCENE 3 — it shows, it does not block =====
      if (a3 > 0) {
        c.save(); c.globalAlpha = a3;
        // a framed finding card
        const cw = W * 0.6, ch = 150, x = cx - cw / 2, y = cy - 120;
        const pop = spring(ctx.p(t, 9.9, 0.7));
        c.save(); c.translate(cx, y + ch / 2); c.scale(lerp(0.92, 1, cl(pop)), lerp(0.92, 1, cl(pop))); c.translate(-cx, -(y + ch / 2));
        c.fillStyle = '#12201B'; rr(c, x, y, cw, ch, 18); c.fill();
        c.strokeStyle = 'rgba(95,191,163,0.8)'; c.lineWidth = 3; rr(c, x, y, cw, ch, 18); c.stroke();
        tracked(c, 'AI assistant can run commands here', x + 40, y + 62, 36, 600, '#EAF1EE', 0, 'left');
        tracked(c, 'DSK-AI-002', x + 40, y + 104, 24, 700, '#7FA89B', 3, 'left');
        tracked(c, 'FLAGGED', x + cw - 40, y + 62, 28, 800, KELPB, 4, 'right');
        tracked(c, 'SHOWN TO YOU — NOT CHANGED', x + cw - 40, y + 104, 22, 700, '#9AA19E', 3, 'right');
        c.restore();
        const w1 = eo(ctx.p(t, 11.0, 0.8));
        if (w1 > 0) { c.globalAlpha = a3 * w1;
          tracked(c, 'Blanktick shows what can reach in.', W * 0.5, H * 0.82, 46, 600, INK, 0, 'center');
          tracked(c, 'It changes nothing without you.', W * 0.5, H * 0.89, 34, 500, MUT, 0, 'center'); }
        c.restore();
      }

      // ===== SCENE 4 — end card =====
      if (a4 > 0) {
        c.save(); c.globalAlpha = a4;
        const mp = eo5(ctx.p(t, 14.2, 0.9));
        mark(c, cx, H * 0.34, 1.7, mp);
        const wm = eo(ctx.p(t, 14.7, 0.7));
        if (wm > 0) { c.globalAlpha = a4 * wm;
          tracked(c, 'blanktick', W * 0.5, H * 0.52, 96, 800, INK, -1, 'center'); }
        const tg = eo(ctx.p(t, 15.1, 0.7));
        if (tg > 0) { c.globalAlpha = a4 * tg;
          tracked(c, 'It shows what others don’t check.', W * 0.5, H * 0.6, 36, 500, MUT, 0, 'center'); }
        // pills
        const pills = ['Offline', 'Nothing leaves your computer', 'Free & open source'];
        const pp = eo(ctx.p(t, 15.6, 0.8));
        if (pp > 0) {
          c.globalAlpha = a4 * pp; font(c, 26, 600);
          const gap = 20, padx = 26; let tw = 0; const ws = pills.map(p => { const w = textW(c, p, 26, 600) + padx * 2; tw += w; return w; }); tw += gap * (pills.length - 1);
          let px = cx - tw / 2; const py = H * 0.68;
          pills.forEach((p, i) => { const w = ws[i];
            c.fillStyle = SUNK; c.strokeStyle = HAIR; c.lineWidth = 2; rr(c, px, py, w, 48, 24); c.fill(); c.stroke();
            c.fillStyle = KELP; c.beginPath(); c.arc(px + padx - 6, py + 24, 4, 0, 7); c.fill();
            tracked(c, p, px + padx + 6, py + 32, 26, 600, INK, 0, 'left');
            px += w + gap; });
        }
        c.restore();
      }

      c.restore();
    }
  };
})();
