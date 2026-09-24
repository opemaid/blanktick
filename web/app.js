/* ------------------------------------------------------------------ *
   Blanktick marketing site.

   The link checker below is a faithful JavaScript port of
   core/src/main/kotlin/com/blanktick/core/analysis/UrlAnalyzer.kt — same
   signal IDs, same weights, same verdict thresholds, same Punycode
   decoder and confusable table.

   It runs entirely in the page. There is no fetch() in this file, which
   is the point: the site demonstrates the product's central claim by
   behaving the same way the product does.
 * ------------------------------------------------------------------ */

'use strict';

/* ---------------------------------------------------- RFC 3492 decode */

const Punycode = (() => {
  const BASE = 36, TMIN = 1, TMAX = 26, SKEW = 38, DAMP = 700;
  const INITIAL_BIAS = 72, INITIAL_N = 128, MAX_OUT = 256;

  const digit = c => {
    if (c >= 'a' && c <= 'z') return c.charCodeAt(0) - 97;
    if (c >= 'A' && c <= 'Z') return c.charCodeAt(0) - 65;
    if (c >= '0' && c <= '9') return c.charCodeAt(0) - 48 + 26;
    return null;
  };

  const adapt = (delta, numPoints, firstTime) => {
    let d = firstTime ? Math.floor(delta / DAMP) : Math.floor(delta / 2);
    d += Math.floor(d / numPoints);
    let k = 0;
    while (d > Math.floor(((BASE - TMIN) * TMAX) / 2)) {
      d = Math.floor(d / (BASE - TMIN));
      k += BASE;
    }
    return k + Math.floor(((BASE - TMIN + 1) * d) / (d + SKEW));
  };

  function decodeLabel(encoded) {
    if (!encoded) return null;
    const output = [];
    const last = encoded.lastIndexOf('-');
    let idx = 0;
    if (last > 0) {
      for (let i = 0; i < last; i++) {
        if (encoded.charCodeAt(i) >= 0x80) return null;
        output.push(encoded.charCodeAt(i));
      }
      idx = last + 1;
    }
    let n = INITIAL_N, i = 0, bias = INITIAL_BIAS;
    while (idx < encoded.length) {
      const oldI = i;
      let w = 1, k = BASE;
      for (;;) {
        if (idx >= encoded.length) return null;
        const d = digit(encoded[idx++]);
        if (d === null) return null;
        i += d * w;
        if (!Number.isSafeInteger(i)) return null;
        const t = k <= bias ? TMIN : (k >= bias + TMAX ? TMAX : k - bias);
        if (d < t) break;
        w *= (BASE - t);
        k += BASE;
      }
      const outLen = output.length + 1;
      if (outLen > MAX_OUT) return null;
      bias = adapt(i - oldI, outLen, oldI === 0);
      n += Math.floor(i / outLen);
      i %= outLen;
      if (n < 0 || n > 0x10FFFF || (n >= 0xD800 && n <= 0xDFFF)) return null;
      output.splice(i, 0, n);
      i++;
    }
    return String.fromCodePoint(...output);
  }

  const decodeHostname = host => {
    if (!/xn--/i.test(host)) return host;
    return host.split('.').map(l =>
      /^xn--/i.test(l) ? (decodeLabel(l.slice(4)) ?? l) : l
    ).join('.');
  };

  return { decodeLabel, decodeHostname, hasAce: h => /(^|\.)xn--/i.test(h) };
})();

/* ------------------------------------------------- confusable folding */

const FOLD = (() => {
  const m = new Map();
  const put = (cp, ch) => m.set(cp, ch);
  // Cyrillic
  [[0x430,'a'],[0x410,'a'],[0x432,'b'],[0x412,'b'],[0x441,'c'],[0x421,'c'],
   [0x435,'e'],[0x415,'e'],[0x440,'p'],[0x420,'p'],[0x445,'x'],[0x425,'x'],
   [0x443,'y'],[0x423,'y'],[0x43E,'o'],[0x41E,'o'],[0x456,'i'],[0x406,'i'],
   [0x458,'j'],[0x408,'j'],[0x455,'s'],[0x405,'s'],[0x43A,'k'],[0x41A,'k'],
   [0x43C,'m'],[0x41C,'m'],[0x43D,'h'],[0x41D,'h'],[0x442,'t'],[0x422,'t'],
   [0x433,'r'],[0x4CF,'l'],[0x499,'z'],
  // Greek
   [0x3B1,'a'],[0x391,'a'],[0x3B2,'b'],[0x392,'b'],[0x3B5,'e'],[0x395,'e'],
   [0x3BF,'o'],[0x39F,'o'],[0x3C1,'p'],[0x3A1,'p'],[0x3C5,'u'],[0x3BD,'v'],
   [0x3C4,'t'],[0x3A4,'t'],[0x397,'h'],[0x39A,'k'],[0x39C,'m'],[0x39D,'n'],
   [0x399,'i'],[0x3A7,'x'],[0x396,'z'],
  // Latin extended
   [0x131,'i'],[0x142,'l'],[0xE0,'a'],[0xE1,'a'],[0xE2,'a'],[0xE3,'a'],[0xE4,'a'],
   [0xE5,'a'],[0xE8,'e'],[0xE9,'e'],[0xEA,'e'],[0xEB,'e'],[0xEC,'i'],[0xED,'i'],
   [0xEE,'i'],[0xEF,'i'],[0xF2,'o'],[0xF3,'o'],[0xF4,'o'],[0xF5,'o'],[0xF6,'o'],
   [0xF8,'o'],[0xF9,'u'],[0xFA,'u'],[0xFB,'u'],[0xFC,'u'],[0xE7,'c'],[0xF1,'n'],
   [0xFD,'y'],[0xFF,'y']].forEach(([cp, ch]) => put(cp, ch));
  // Full-width Latin
  for (let i = 0; i < 26; i++) {
    put(0xFF41 + i, String.fromCharCode(97 + i));
    put(0xFF21 + i, String.fromCharCode(97 + i));
  }
  return m;
})();

const skeleton = label =>
  [...label].map(ch => FOLD.get(ch.codePointAt(0)) ?? ch.toLowerCase()).join('');

const scriptOf = cp => {
  if ((cp >= 0x41 && cp <= 0x5A) || (cp >= 0x61 && cp <= 0x7A) || (cp >= 0xC0 && cp <= 0x24F)) return 'LATIN';
  if ((cp >= 0x30 && cp <= 0x39) || cp === 0x2D || cp === 0x2E || cp === 0x5F) return 'COMMON';
  if (cp >= 0x370 && cp <= 0x3FF) return 'GREEK';
  if (cp >= 0x400 && cp <= 0x52F) return 'CYRILLIC';
  if (cp >= 0x530 && cp <= 0x58F) return 'ARMENIAN';
  if ((cp >= 0xFF21 && cp <= 0xFF3A) || (cp >= 0xFF41 && cp <= 0xFF5A)) return 'LATIN';
  if (cp >= 0x2E80) return 'CJK';
  return 'OTHER';
};

// Whole-script labels are NOT flagged: ordinary Russian, Greek and Japanese
// domains must not read as attacks. Only Latin mixed with a lookalike script.
const suspiciousMix = label => {
  const s = new Set([...label].map(c => scriptOf(c.codePointAt(0))).filter(x => x !== 'COMMON'));
  if (s.size < 2) return false;
  if (s.has('LATIN') && (s.has('CYRILLIC') || s.has('GREEK') || s.has('ARMENIAN'))) return true;
  return s.has('CYRILLIC') && s.has('GREEK');
};

/* ------------------------------------------------------ public suffix */

const MULTI = new Set([
  'co.uk','org.uk','me.uk','ac.uk','gov.uk','com.au','net.au','org.au','co.nz',
  'co.za','org.za','net.za','gov.za','ac.za','com.br','com.ar','com.mx','com.co',
  'co.jp','co.kr','com.cn','com.hk','com.tw','com.sg','com.my','com.ph','com.vn',
  'co.th','co.id','co.il','co.in','net.in','gov.in','com.pk','com.bd','com.sa',
  'com.eg','com.tr','com.ng','com.gh','co.ke','co.tz','com.es','com.pl','com.pt',
  'com.ua','com.ru','github.io','netlify.app','vercel.app','pages.dev','web.app',
  'herokuapp.com','blogspot.com','wordpress.com','wixsite.com','myshopify.com',
  'repl.co','ngrok.io','ngrok-free.app','trycloudflare.com','duckdns.org','onrender.com'
]);

const isIp = h => {
  if (h.startsWith('[') && h.endsWith(']')) return true;
  const p = h.split('.');
  if (p.length === 4 && p.every(x => x.length && /^\d+$/.test(x))) return p.every(x => +x <= 255);
  if (p.length === 1) {
    if (/^\d{8,10}$/.test(h)) return true;
    if (/^0x[0-9a-f]+$/i.test(h)) return true;
  }
  return false;
};

const registrable = host => {
  if (isIp(host)) return host;
  const l = host.split('.').filter(Boolean);
  if (l.length <= 2) return host;
  return MULTI.has(l.slice(-2).join('.')) ? l.slice(-3).join('.') : l.slice(-2).join('.');
};

const subLabels = host => {
  const r = registrable(host);
  return host === r ? [] : host.slice(0, -(r.length + 1)).split('.').filter(Boolean);
};

/* ---------------------------------------------------------- constants */

const BRANDS = new Set([
  'google.com','gmail.com','youtube.com','microsoft.com','outlook.com','office.com',
  'apple.com','icloud.com','amazon.com','facebook.com','instagram.com','whatsapp.com',
  'linkedin.com','netflix.com','spotify.com','dropbox.com','github.com','slack.com',
  'paypal.com','stripe.com','wise.com','revolut.com','coinbase.com','binance.com',
  'kraken.com','metamask.io','ledger.com','hsbc.com','barclays.co.uk','citi.com',
  'chase.com','wellsfargo.com','bankofamerica.com','natwest.com',
  'standardbank.co.za','fnb.co.za','absa.co.za','nedbank.co.za','capitecbank.co.za',
  'discovery.co.za','investec.com','tymebank.co.za','sars.gov.za','takealot.com',
  'vodacom.co.za','mtn.co.za','telkom.co.za','checkers.co.za','woolworths.co.za',
  'dhl.com','fedex.com','ups.com','usps.com','royalmail.com','aramex.com'
]);

const SHORTENERS = new Set(['bit.ly','tinyurl.com','t.co','goo.gl','ow.ly','is.gd',
  'buff.ly','rebrand.ly','cutt.ly','shorturl.at','rb.gy','t.ly','lnkd.in','youtu.be',
  'amzn.to','fb.me','wa.me']);

const RISKY_TLDS = new Set(['tk','ml','ga','cf','gq','top','xyz','click','link','work',
  'zip','mov','loan','date','racing','download','review','stream','science','party',
  'bid','trade','win','rest','quest','cyou','sbs','cfd']);

const EXEC_SCHEMES = new Set(['javascript','data','vbscript','file','intent','jar']);

/* ------------------------------------------------- bounded edit distance */

function editDistance(a, b, limit) {
  if (a === b) return 0;
  if (Math.abs(a.length - b.length) > limit) return limit + 1;
  if (!a.length) return b.length;
  if (!b.length) return a.length;
  let pp = new Array(b.length + 1).fill(0);
  let prev = Array.from({ length: b.length + 1 }, (_, i) => i);
  let cur = new Array(b.length + 1).fill(0);
  for (let i = 1; i <= a.length; i++) {
    cur[0] = i;
    let rowMin = i;
    for (let j = 1; j <= b.length; j++) {
      const cost = a[i - 1] === b[j - 1] ? 0 : 1;
      let v = Math.min(cur[j - 1] + 1, prev[j] + 1, prev[j - 1] + cost);
      if (i > 1 && j > 1 && a[i - 1] === b[j - 2] && a[i - 2] === b[j - 1]) {
        v = Math.min(v, pp[j - 2] + cost);
      }
      cur[j] = v;
      if (v < rowMin) rowMin = v;
    }
    if (rowMin > limit) return limit + 1;
    [pp, prev, cur] = [prev, cur, pp];
  }
  return prev[b.length];
}

/* -------------------------------------------------------------- parser */

function parseUrl(input) {
  const t = input.trim();
  if (!t) return null;
  let rest = t, scheme = null;
  const c = rest.indexOf(':');
  if (c > 0 && /^[a-z][a-z0-9+\-.]*$/i.test(rest.slice(0, c))) {
    scheme = rest.slice(0, c).toLowerCase();
    rest = rest.slice(c + 1);
    if (rest.startsWith('//')) rest = rest.slice(2);
  }
  if (scheme && EXEC_SCHEMES.has(scheme)) return { scheme, host: '', exec: true };

  let fragment = null, query = null;
  const h = rest.indexOf('#'); if (h >= 0) { fragment = rest.slice(h + 1); rest = rest.slice(0, h); }
  const q = rest.indexOf('?'); if (q >= 0) { query = rest.slice(q + 1); rest = rest.slice(0, q); }
  let path = '/';
  const s = rest.indexOf('/'); if (s >= 0) { path = rest.slice(s); rest = rest.slice(0, s); }

  let userInfo = null;
  const at = rest.lastIndexOf('@');
  if (at >= 0) { userInfo = rest.slice(0, at); rest = rest.slice(at + 1); }

  let port = null, host = rest;
  if (host.startsWith('[')) {
    const close = host.indexOf(']');
    if (close < 0) return null;
    const after = host.slice(close + 1);
    if (after.startsWith(':')) port = parseInt(after.slice(1), 10);
    host = host.slice(0, close + 1);
  } else {
    const colon = host.lastIndexOf(':');
    if (colon >= 0 && /^\d+$/.test(host.slice(colon + 1))) {
      port = parseInt(host.slice(colon + 1), 10);
      host = host.slice(0, colon);
    }
  }
  host = host.toLowerCase().replace(/\.$/, '');
  if (!host) return null;
  if ((scheme === 'https' && port === 443) || (scheme === 'http' && port === 80)) port = null;
  return { scheme, userInfo, host, port, path, query, fragment, exec: false };
}

/* ------------------------------------------------------------ analyzer */

function analyze(input) {
  const p = parseUrl(input);
  if (!p) {
    return { verdict: 'SUSPICIOUS', risk: 45, signals: [{ w: 45,
      t: 'This does not look like a valid web address, which is itself unusual in a message asking you to click something.' }] };
  }
  if (p.exec) {
    return { verdict: 'DANGEROUS', risk: 95, signals: [{ w: 95,
      t: `This is not a web address — it is a command ("${p.scheme}:"). Opening it runs code rather than visiting a page.` }] };
  }

  const signals = [];
  const host = p.host;
  const display = Punycode.decodeHostname(host);
  const reg = registrable(host);
  let impersonated = null;

  const allowlisted = BRANDS.has(reg);

  if (p.userInfo) signals.push({ w: 60, id: 'USERINFO',
    t: `Everything before the "@" is ignored by the browser. This link actually goes to "${display}", not to what it appears to say.` });

  if (isIp(host)) signals.push({ w: 45, id: 'IP',
    t: 'This link points at a bare numeric address rather than a domain name. Legitimate businesses do not send links like this.' });

  if (!isIp(host)) {
    const mixed = display.split('.').find(suspiciousMix);
    if (mixed) signals.push({ w: 75, id: 'MIXED',
      t: `The address mixes alphabets inside "${mixed}" — for example a Cyrillic letter among Latin ones. This is done to make a fake address look identical to a real one.` });

    if ([...display].some(ch => ch.codePointAt(0) > 0x7F)) {
      const skelHost = display.split('.').map(skeleton).join('.');
      const skelReg = registrable(skelHost);
      if (skelReg !== reg && BRANDS.has(skelReg)) {
        impersonated = skelReg;
        signals.push({ w: 100, id: 'HOMOGLYPH',
          t: `This address is built from letters that look like "${skelReg}" but are different characters. It is a deliberate imitation.` });
      }
    }
  }

  if (!isIp(host) && !BRANDS.has(reg)) {
    const subs = subLabels(display);
    let brandInSub = null;
    for (const label of subs) {
      const sk = skeleton(label);
      const found = [...BRANDS].find(b => b.split('.')[0] === sk);
      if (found) { brandInSub = found; break; }
    }
    if (brandInSub) {
      impersonated ??= brandInSub;
      signals.push({ w: 85, id: 'BRAND-SUB',
        t: `"${brandInSub.split('.')[0]}" appears in this address, but the site it actually goes to is "${reg}". The part that matters is the one just before the first single slash.` });
    }
  }

  if (!isIp(host) && !BRANDS.has(reg)) {
    const name = skeleton(reg).split('.')[0];
    if (name.length >= 5) {
      let best = null;
      for (const b of BRANDS) {
        const bn = b.split('.')[0];
        if (bn === name) { best = null; break; }
        if (Math.abs(bn.length - name.length) > 2) continue;
        const d = editDistance(name, bn, 2);
        if (d >= 1 && d <= 2 && (!best || d < best[1])) best = [b, d];
      }
      if (best) {
        impersonated ??= best[0];
        signals.push({ w: 70, id: 'TYPO',
          t: `"${reg}" is only ${best[1]} character${best[1] > 1 ? 's' : ''} away from "${best[0]}". Misspelled lookalike domains are registered specifically to catch people who mistype or skim.` });
      }
    }
  }

  const depth = subLabels(host).length;
  if (depth >= 4) signals.push({ w: 30, id: 'DEEP',
    t: `This address has ${depth} levels of subdomain, which is a common way to push the real destination out of sight on a phone screen.` });

  if (p.port && ![80, 443, 8443].includes(p.port)) signals.push({ w: 35, id: 'PORT',
    t: `This link connects on port ${p.port} instead of the normal web ports.` });

  if (input.length > 150) signals.push({ w: 15, id: 'LEN',
    t: `This address is unusually long (${input.length} characters), which is often used to hide the real destination.` });

  const enc = (input.split('%').length - 1) * 3 / Math.max(input.length, 1);
  if (enc > 0.15) signals.push({ w: 40, id: 'ENC',
    t: 'A large part of this address is written in escape codes rather than plain text, which is normally done to disguise it.' });

  if (p.scheme === 'http') signals.push({ w: 20, id: 'NOTLS',
    t: 'This link is not encrypted. Anything you type into the page can be read in transit.' });

  const tld = host.split('.').pop();
  if (RISKY_TLDS.has(tld)) signals.push({ w: 25, id: 'TLD',
    t: `".${tld}" addresses are given away cheaply or free and are used disproportionately for scams.` });

  const shortener = SHORTENERS.has(reg) || SHORTENERS.has(host);
  if (shortener) signals.push({ w: 0, id: 'SHORT',
    t: 'This is a shortened link. Blanktick works offline and cannot follow it to see where it really goes, so it cannot tell you whether the destination is safe.' });

  const risk = Math.min(100, signals.reduce((a, s) => a + s.w, 0));

  let verdict;
  if (allowlisted && risk < 70) verdict = 'SAFE';
  else if (risk >= 70) verdict = 'DANGEROUS';
  else if (risk >= 35) verdict = 'SUSPICIOUS';
  else verdict = 'UNKNOWN';   // never SAFE for an unverified domain

  signals.sort((a, b) => b.w - a.w);
  return { verdict, risk, signals, host, display, reg, impersonated };
}

/* ---------------------------------------------------------------- UI */

const esc = s => String(s).replace(/[&<>"]/g, c => ({ '&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;' }[c]));

const COPY = {
  SAFE:       ['Known good', 'This is a domain Blanktick recognises. Still check the page itself before typing a password.'],
  UNKNOWN:    ['Unknown', 'Blanktick found nothing wrong with the structure of this address — but working offline it cannot confirm the site is genuinely safe, so it will not say so.'],
  SUSPICIOUS: ['Suspicious', 'Several things about this address are unusual. Treat it as untrusted.'],
  DANGEROUS:  ['Dangerous', 'This address is built to be mistaken for something else.']
};

function highlightHost(res) {
  if (!res.host) return '';
  const reg = res.reg || '';
  const display = res.display || res.host;
  if (!display.endsWith(reg)) return esc(display);
  const prefix = display.slice(0, display.length - reg.length);
  return `<span class="bad">${esc(prefix.replace(/\.$/, ''))}</span>${prefix ? '.' : ''}<span class="real">${esc(reg)}</span>`;
}

function renderResult(input) {
  const out = document.getElementById('result');
  const r = analyze(input);
  const [label, blurb] = COPY[r.verdict];

  out.innerHTML = `
    <span class="verdict-badge v-${r.verdict.toLowerCase()}">${label}</span>
    <h4>${esc(blurb)}</h4>
    ${r.host ? `<div class="host">${highlightHost(r)}</div>` : ''}
    ${r.impersonated ? `<p style="margin:1rem 0 0;color:var(--inkMuted);font-size:0.95rem">
        Appears to imitate <strong style="color:var(--ink)">${esc(r.impersonated)}</strong>.</p>` : ''}
    <div style="margin-top:1.25rem">
      ${r.signals.map(s => `<div class="sig"><span class="w">${s.w || '—'}</span><span>${esc(s.t)}</span></div>`).join('')}
    </div>
    <p style="margin-top:1.25rem;font-size:0.82rem;color:var(--inkFaint);line-height:1.6">
      Risk score ${r.risk}/100 · computed in this page · no request was made.
    </p>`;
}

document.addEventListener('DOMContentLoaded', () => {
  const input = document.getElementById('url');

  document.getElementById('check').addEventListener('click', () => renderResult(input.value));
  input.addEventListener('keydown', e => { if (e.key === 'Enter') renderResult(input.value); });

  document.querySelectorAll('.samples button').forEach(b => {
    b.addEventListener('click', () => { input.value = b.dataset.url; renderResult(b.dataset.url); });
  });

  renderResult(input.value);

  // Anything already on screen at first paint is revealed immediately.
  // Staggering the hero means the page loads visibly incomplete, which is a
  // worse first impression than no animation at all.
  const all = [...document.querySelectorAll('[data-reveal]')];
  const fold = window.innerHeight;
  const below = all.filter(el => {
    if (el.getBoundingClientRect().top < fold * 0.9) { el.classList.add('in'); return false; }
    return true;
  });

  // Scroll reveal via IntersectionObserver — never a scroll listener.
  const io = new IntersectionObserver(entries => {
    entries.forEach((e, i) => {
      if (!e.isIntersecting) return;
      setTimeout(() => e.target.classList.add('in'), i * 70);
      io.unobserve(e.target);
    });
  }, { rootMargin: '0px 0px -8% 0px', threshold: 0.05 });
  below.forEach(el => io.observe(el));

  // Last-resort reveal. If the observer has not fired for an element after
  // eight seconds -- a browser that never scrolls, a print/reader view, a
  // preview renderer -- show it anyway. Content that exists but can never be
  // seen is worse than content that arrives without its animation.
  setTimeout(() => all.forEach(el => el.classList.add('in')), 8000);

  // Theme toggle, remembering the choice for this browser only.
  const root = document.documentElement;
  const saved = localStorage.getItem('blanktick-theme');
  if (saved) root.dataset.theme = saved;
  document.getElementById('theme').addEventListener('click', () => {
    const next = root.dataset.theme === 'dark' ? 'light' : 'dark';
    root.dataset.theme = next;
    localStorage.setItem('blanktick-theme', next);
  });
});
