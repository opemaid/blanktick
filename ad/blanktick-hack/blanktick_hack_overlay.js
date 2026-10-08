// blanktick_hack_overlay — transparent neon HUD painted over the reference
// "AI hacking" footage. Targeting reticle locks the core, intrusion readout
// types in, glitch headline. Ends on a lime pre-ignite + white flash that the
// resolve clip catches. 720x1280, --alpha. Does NOT paint a background.
(function () {
  const MO = window.MO, U = window.U, cl = U.clamp, lerp = U.lerp;
  const NEON = '#3DFF78', NEOND = '#1FBF55', ALERT = '#FF3B30', CYAN = '#4FE6FF', LIME = '#E4FF5A', INK = '#02110A';
  const MONO = '"Consolas", "Courier New", monospace';
  const DISP = '"Arial Black", Impact, sans-serif';

  function txt(c, s, x, y, px, w, col, fam, align = 'left', track = 0) {
    c.font = `${w} ${px}px ${fam}`; c.fillStyle = col; c.textBaseline = 'alphabetic';
    let tot = 0; const chs = [...s]; for (const ch of chs) tot += c.measureText(ch).width + track; tot -= track;
    let sx = align === 'center' ? x - tot / 2 : align === 'right' ? x - tot : x;
    for (const ch of chs) { c.fillText(ch, sx, y); sx += c.measureText(ch).width + track; } return tot;
  }
  function glitchTxt(c, s, x, y, px, w, fam, t, amp) {
    const dx = (Math.sin(t * 37) + Math.sin(t * 19.3)) * amp, dy = Math.sin(t * 53) * amp * 0.4;
    c.save(); c.globalCompositeOperation = 'lighter';
    txt(c, s, x + dx + 3, y + dy, px, w, 'rgba(255,40,40,0.9)', fam, 'center');
    txt(c, s, x - dx - 3, y - dy, px, w, 'rgba(60,230,255,0.9)', fam, 'center');
    c.restore();
    txt(c, s, x, y, px, w, '#EAFFF0', fam, 'center');
  }

  const CLIPS = (window.CLIPS = window.CLIPS || {});
  CLIPS.blanktick_hack_overlay = {
    draw(c, t, ctx) {
      const W = ctx.W, H = ctx.H, cx = W / 2, cy = H * 0.52;

      // scanlines (moving), subtle
      c.save(); c.globalAlpha = 0.10; c.fillStyle = NEON;
      const off = (t * 40) % 6; for (let y = -6 + off; y < H; y += 6) c.fillRect(0, y, W, 1.5); c.restore();
      // occasional glitch slice
      const gl = Math.sin(t * 7.1) > 0.92 ? 1 : 0;
      if (gl) { c.save(); c.globalAlpha = 0.25; c.fillStyle = CYAN; const gy = ((t * 997) % H); c.fillRect(0, gy, W, 10 + 40 * Math.abs(Math.sin(t * 11))); c.restore(); }

      // top HUD bar (also masks the sliver of room)
      const g = c.createLinearGradient(0, 0, 0, 170); g.addColorStop(0, 'rgba(0,10,6,0.95)'); g.addColorStop(1, 'rgba(0,10,6,0)');
      c.fillStyle = g; c.fillRect(0, 0, W, 170);
      txt(c, 'SYS://INTRUSION DETECTED', 28, 64, 26, 700, NEON, MONO, 'left', 1);
      const blink = (Math.floor(t * 2) % 2) === 0;
      if (blink) { c.fillStyle = ALERT; c.beginPath(); c.arc(W - 150, 57, 8, 0, 7); c.fill(); }
      txt(c, 'REC', W - 132, 64, 24, 700, ALERT, MONO, 'left', 1);
      txt(c, '00:0' + (t).toFixed(2), 28, 98, 20, 400, NEOND, MONO, 'left', 1);

      // corner targeting brackets (tighten in, then jitter)
      const tin = MO.expoOut(cl(t / 0.6)); const pad = lerp(10, 54, tin) + Math.sin(t * 20) * 2, L = 54;
      c.strokeStyle = NEON; c.lineWidth = 4; c.lineCap = 'square';
      const corner = (x, y, sx, sy) => { c.beginPath(); c.moveTo(x + sx * L, y); c.lineTo(x, y); c.lineTo(x, y + sy * L); c.stroke(); };
      corner(pad, 188 + pad * 0, 1, 1); corner(W - pad, 188, -1, 1); corner(pad, H - pad, 1, -1); corner(W - pad, H - pad, -1, -1);

      // center reticle locking the core
      const lock = t > 3.8;
      c.save(); c.translate(cx, cy);
      c.strokeStyle = lock ? ALERT : NEON; c.lineWidth = 3;
      // rotating dashed ring
      const rr = 150 + Math.sin(t * 3) * 6; c.save(); c.rotate(t * (lock ? 2.4 : 1.1)); c.setLineDash([18, 16]); c.beginPath(); c.arc(0, 0, rr, 0, 7); c.stroke(); c.setLineDash([]); c.restore();
      // tightening square brackets
      const sb = lerp(230, 120, MO.expoOut(cl(t / 3.8))) + (lock ? Math.sin(t * 30) * 3 : 0);
      for (const [sx, sy] of [[-1, -1], [1, -1], [-1, 1], [1, 1]]) { const bx = sx * sb, by = sy * sb;
        c.beginPath(); c.moveTo(bx - sx * 36, by); c.lineTo(bx, by); c.lineTo(bx, by - sy * 36); c.stroke(); }
      // crosshair
      c.globalAlpha = 0.8; c.beginPath(); c.moveTo(-rr, 0); c.lineTo(-40, 0); c.moveTo(40, 0); c.lineTo(rr, 0); c.moveTo(0, -rr); c.lineTo(0, -40); c.moveTo(0, 40); c.lineTo(0, rr); c.stroke(); c.globalAlpha = 1;
      txt(c, lock ? 'LOCKED' : 'LOCKING', 0, -sb - 18, 22, 700, lock ? ALERT : NEON, MONO, 'center', 2);
      c.restore();

      // intrusion readout (left), one line per ~0.7s, truthful-ish core line in alert
      const lines = [
        ['> scanning host ...', NEON],
        ['> AI assistant found', NEON],
        ['> can run commands: YES', ALERT],
        ['> reading files / clipboard', NEON],
        ['> exfil path: OPEN', ALERT]
      ];
      c.save(); let ly = 240;
      for (let i = 0; i < lines.length; i++) { const at = 0.8 + i * 0.7; if (t < at) break; const a = cl((t - at) / 0.2);
        c.globalAlpha = a * 0.95; txt(c, lines[i][0], 30, ly, 24, 700, lines[i][1], MONO, 'left', 0.5); ly += 36; }
      c.restore();

      // glitch headline (bottom third)
      if (t > 1.4) { const fl = Math.sin(t * 22) > -0.6 ? 1 : 0.3;
        c.save(); c.globalAlpha = fl; glitchTxt(c, 'AI IS IN YOUR PC', cx, H * 0.80, 70, 900, DISP, t, 4 + (lock ? 3 : 0)); c.restore();
        if (t > 2.1) { c.globalAlpha = cl((t - 2.1) / 0.3); txt(c, 'An AI assistant can run commands here.', cx, H * 0.80 + 44, 26, 600, NEON, MONO, 'center', 0.5); c.globalAlpha = 1; }
      }

      // pre-ignite lime pulse from center (6.2 -> 7.0) then white flash catches the cut
      if (t > 6.15) { const p = (t - 6.15) / 0.85; const r = lerp(30, Math.max(W, H), MO.expoIn(p));
        c.save(); c.globalCompositeOperation = 'lighter'; c.globalAlpha = cl(1 - p * 0.3); c.strokeStyle = LIME; c.lineWidth = lerp(8, 46, p);
        c.beginPath(); c.arc(cx, cy, r, 0, 7); c.stroke(); c.restore(); }
      if (t > 6.6) { const fa = cl((t - 6.6) / 0.4); c.save(); c.globalAlpha = fa * 0.96; c.fillStyle = '#F4FFE0'; c.fillRect(0, 0, W, H); c.restore(); }
    }
  };
})();
