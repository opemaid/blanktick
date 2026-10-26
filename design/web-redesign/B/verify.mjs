/**
 * Parity harness for the site's link checker.
 *
 *     node web/verify.mjs
 *
 * The browser build of the analyzer is a port of UrlAnalyzer.kt, and a port
 * that silently diverges is worse than no port at all -- the marketing site
 * would be demonstrating behaviour the app does not have. So the same
 * expectations that the Kotlin test suite asserts are re-asserted here
 * against the JavaScript.
 *
 * app.js is written for a browser, so we stub the two globals it touches at
 * load time and then reach into its functions.
 */

import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import path from 'node:path';
import vm from 'node:vm';

const here = path.dirname(fileURLToPath(import.meta.url));
const source = readFileSync(path.join(here, 'app.js'), 'utf8');

// Minimal DOM stub: app.js only registers a DOMContentLoaded listener at load.
const sandbox = {
  document: { addEventListener() {}, querySelectorAll: () => [], getElementById: () => null },
  window: {},
  localStorage: { getItem: () => null, setItem() {} },
  IntersectionObserver: class { observe() {} unobserve() {} },
  console,
};
sandbox.globalThis = sandbox;
vm.createContext(sandbox);
vm.runInContext(source + '\n;globalThis.__api = { analyze, parseUrl, skeleton, editDistance, Punycode, registrable, subLabels };', sandbox);

const { analyze, parseUrl, skeleton, editDistance, Punycode, registrable } = sandbox.__api;

let passed = 0;
const failures = [];

function check(name, fn) {
  try {
    fn();
    passed++;
  } catch (e) {
    failures.push(`${name}\n    ${e.message}`);
  }
}
const eq = (a, b, msg = '') => {
  if (a !== b) throw new Error(`expected ${JSON.stringify(b)}, got ${JSON.stringify(a)} ${msg}`);
};
const ok = (v, msg = '') => { if (!v) throw new Error(`expected truthy ${msg}`); };

/* ---- Punycode: the same textbook vectors the Kotlin suite pins ---- */

check('punycode: bücher', () => eq(Punycode.decodeLabel('bcher-kva'), 'bücher'));
check('punycode: münchen', () => eq(Punycode.decodeLabel('mnchen-3ya'), 'münchen'));
check('punycode: café', () => eq(Punycode.decodeLabel('caf-dma'), 'café'));
check('punycode: hostname leaves ascii alone', () =>
  eq(Punycode.decodeHostname('xn--bcher-kva.example.com'), 'bücher.example.com'));
check('punycode: invalid returns null', () => eq(Punycode.decodeLabel('!!!'), null));

/* ---- confusable folding ---- */

check('skeleton: cyrillic paypal folds to latin', () => eq(skeleton('раураӏ'), 'paypal'));
check('skeleton: digits are NOT folded', () => eq(skeleton('g00gle'), 'g00gle'));
check('skeleton: full-width folds', () => eq(skeleton('ｐａｙｐａｌ'), 'paypal'));

/* ---- parser: the attacks that break naive parsers ---- */

check('parser: last @ wins', () => eq(parseUrl('https://paypal.com@evil.ru/login').host, 'evil.ru'));
check('parser: multiple @', () => eq(parseUrl('https://a@b@c@real.example/x').host, 'real.example'));
check('parser: ipv6 with port', () => {
  const u = parseUrl('https://[2001:db8::1]:8080/x');
  eq(u.host, '[2001:db8::1]'); eq(u.port, 8080);
});
check('parser: default port normalised away', () => eq(parseUrl('https://example.com:443/').port, null));
check('parser: trailing dot stripped', () => eq(parseUrl('https://example.com./x').host, 'example.com'));

/* ---- public suffix ---- */

check('suffix: co.za is multi-label', () =>
  eq(registrable('www.standardbank.co.za'), 'standardbank.co.za'));
check('suffix: plain com', () => eq(registrable('a.b.example.com'), 'example.com'));

/* ---- edit distance ---- */

check('distance: transposition counts as one', () => eq(editDistance('ab', 'ba', 2), 1));
check('distance: early exit beyond the bound', () => ok(editDistance('aaaaaa', 'bbbbbb', 2) > 2));

/* ---- verdicts: mirrors UrlAnalyzerTest ---- */

check('verdict: brand in subdomain is DANGEROUS', () => {
  const r = analyze('https://standardbank.co.za.verify-account.top/login');
  eq(r.verdict, 'DANGEROUS');
  eq(r.reg, 'verify-account.top');
  ok(r.signals.some(s => s.id === 'BRAND-SUB'));
});

check('verdict: credentials in authority are caught', () => {
  const r = analyze('https://paypal.com@evil-site.ru/signin');
  eq(r.host, 'evil-site.ru');
  ok(r.signals.some(s => s.id === 'USERINFO'));
});

check('verdict: homoglyph is decoded and named', () => {
  const r = analyze('https://xn--pypal-4ve.com/login');
  ok(r.signals.some(s => s.id === 'HOMOGLYPH' || s.id === 'MIXED'),
     `signals were ${r.signals.map(s => s.id)}`);
  eq(r.verdict, 'DANGEROUS');
  ok([...r.display].some(c => c.codePointAt(0) > 0x7f), 'display host must show real characters');
});

check('verdict: typosquat is caught', () => {
  const r = analyze('https://gogle.com');
  ok(r.signals.some(s => s.id === 'TYPO'), `signals were ${r.signals.map(s => s.id)}`);
});

/* ---- combosquatting: mirrors the four URL-COMBOSQUAT tests in AnalysisTest.kt ---- */

check('combosquat: digit-swapped brand with words attached is dangerous', () => {
  const r = analyze('http://paypa1-secure-login.xyz/verify');
  ok(r.signals.some(s => s.id === 'COMBO'), `signals were ${r.signals.map(s => s.id)}`);
  eq(r.impersonated, 'paypal.com'); eq(r.verdict, 'DANGEROUS');
});
check('combosquat: exact brand word is weighted 55', () => {
  const r = analyze('https://paypal-secure-login.com/');
  eq(r.signals.find(s => s.id === 'COMBO')?.w, 55); eq(r.impersonated, 'paypal.com');
});
check('combosquat: ordinary hyphenated names are left alone', () => {
  for (const u of ['https://apples-and-pears.com/', 'https://my-garden-blog.com/',
                   'https://secure-login-help.com/', 'https://top-10-recipes.com/'])
    ok(!analyze(u).signals.some(s => s.id === 'COMBO'), u);
});

check('verdict: the real brand is never flagged', () => {
  const r = analyze('https://www.paypal.com/signin');
  ok(!r.signals.some(s => s.id === 'TYPO'));
  ok(!r.signals.some(s => s.id === 'BRAND-SUB'));
  eq(r.verdict, 'SAFE');
});

check('verdict: raw IP', () => {
  const r = analyze('http://192.168.4.20/bank/login');
  ok(r.signals.some(s => s.id === 'IP'));
});

check('verdict: shortener is UNKNOWN, never SAFE', () => {
  const r = analyze('https://bit.ly/3xYzAbC');
  eq(r.verdict, 'UNKNOWN');
  ok(r.signals.some(s => s.id === 'SHORT'));
});

check('verdict: executable scheme', () => eq(analyze('javascript:alert(1)').verdict, 'DANGEROUS'));

check('verdict: clean unlisted domain is UNKNOWN, not SAFE', () => {
  // The central honesty property. Finding nothing wrong != verified safe.
  const r = analyze('https://some-small-business.co.za/contact');
  eq(r.verdict, 'UNKNOWN');
});

check('verdict: allowlisted brand is SAFE', () =>
  eq(analyze('https://www.google.com/search?q=hello').verdict, 'SAFE'));

check('verdict: risk score is bounded', () => {
  const r = analyze('http://paypal.com@bad.tk:1337/%2e%2e%2e%2e%2e%2e%2e%2e');
  ok(r.risk >= 0 && r.risk <= 100, `risk was ${r.risk}`);
});

check('verdict: malformed input is reported', () => eq(analyze('   ').verdict, 'SUSPICIOUS'));

check('signals are sorted by weight descending', () => {
  const r = analyze('http://paypal.com.evil.tk/login');
  const w = r.signals.map(s => s.w);
  eq(JSON.stringify(w), JSON.stringify([...w].sort((a, b) => b - a)));
});

/* ---- report ---- */

console.log(`\n  ${passed} passed, ${failures.length} failed\n`);
if (failures.length) {
  failures.forEach(f => console.error('  FAIL  ' + f));
  process.exit(1);
}
console.log('  Site link checker matches UrlAnalyzer.kt behaviour.\n');
