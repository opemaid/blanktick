# Assembles index.html / privacy.html / terms.html from *.src.html.
# Dev-time only (not served, not referenced by any page): injects the 81-cell
# matrix and one shared header/footer so the three pages cannot drift apart.
import pathlib, re
D = pathlib.Path(__file__).parent

MARK = ('<svg class="mark" viewBox="0 0 256 256" aria-hidden="true" focusable="false"><rect width="256" height="256" fill="#FBFAF6"/>'
        '<g transform="translate(128 128) scale(0.8) translate(-134 -133)" fill="none" stroke="#0F4D3F" stroke-width="34" stroke-linecap="butt" stroke-linejoin="miter">'
        '<path d="M44 136 L104 192 L150 148"/><path d="M172 126 L224 74"/></g></svg>')

def footer(p, home, current=None, note=True):
    cur = lambda f: ' aria-current="page"' if f == current else ''
    foot_note = '''
    <div class="foot-note">
      <p>
        Blanktick is free and open source under AGPL-3.0. It has had no third-party
        security audit; it is one person&rsquo;s code, and the build gates exist so
        you do not have to take our word for the part that matters.
      </p>
      <p>
        Passing every check is not the same as being safe. It means the checks that
        ran, ran clean &mdash; and the list of the ones that did not is on the same
        screen, at the same size, on purpose.
      </p>
    </div>''' if note else ''
    return f'''<footer class="site">
  <div class="wrap">
    <div class="foot-grid">
      <div class="foot-brand">
        <a class="brand" href="{home}" aria-label="Blanktick, {'back to top' if home == '#main' else 'home'}">
          {MARK}
          <span class="word">blanktick</span>
        </a>
        <p>A free, offline security scanner that tells you what it could not check.</p>
      </div>
      <nav class="foot-col" aria-labelledby="f-product">
        <h2 id="f-product">Product</h2>
        <ul>
          <li><a href="{p}#coverage">Coverage</a></li>
          <li><a href="{p}#looks">What it checks</a></li>
          <li><a href="{p}#offline">Offline design</a></li>
          <li><a href="{p}#download">Download</a></li>
        </ul>
      </nav>
      <nav class="foot-col" aria-labelledby="f-project">
        <h2 id="f-project">Project</h2>
        <ul>
          <li><a href="{p}#about">About &amp; mission</a></li>
          <li><a href="mailto:hello@blanktick.org">Contact</a></li>
          <li><a href="mailto:hello@blanktick.org?subject=Security%20report">Report a vulnerability</a></li>
        </ul>
      </nav>
      <nav class="foot-col" aria-labelledby="f-legal">
        <h2 id="f-legal">Legal</h2>
        <ul>
          <li><a href="privacy.html"{cur('privacy')}>Privacy policy</a></li>
          <li><a href="terms.html"{cur('terms')}>Terms &amp; licence</a></li>
          <li><a href="privacy.html#cookies">Cookies: none</a></li>
        </ul>
      </nav>
    </div>
{foot_note}
    <div class="foot-bar">
      <p>&copy; 2026 Blanktick. Founded by Simphiwe Damoyi, South Africa.</p>
      <p class="foot-proof"><span>No cookies</span><span>No analytics</span><span>No third-party requests</span></p>
    </div>
  </div>
</footer>'''

def header_doc():
    return f'''<header class="site">
  <div class="wrap nav">
    <a class="brand" href="index.html" aria-label="Blanktick, home">
      {MARK}
      <span class="word">blanktick</span>
    </a>
    <nav aria-label="Primary" class="primary">
      <ul class="nav-inline">
          <li><a href="index.html#looks">What it checks</a></li>
          <li><a href="index.html#about">About</a></li>
          <li class="nav-dl"><a href="index.html#download">Download</a></li>
      </ul>
      <details class="menu">
        <summary><span class="burger" aria-hidden="true"></span>Menu</summary>
        <ul>
          <li><a href="index.html#looks">What it checks</a></li>
          <li><a href="index.html#about">About</a></li>
          <li class="nav-dl"><a href="index.html#download">Download</a></li>
        </ul>
      </details>
    </nav>
  </div>
</header>'''

cells = ['<i class="c ok"></i>'] * 50 + ['<i class="c ph"></i>'] * 18 + ['<i class="c os"></i>'] * 13
matrix = '\n'.join('          ' + ''.join(cells[r * 9:(r + 1) * 9]) for r in range(9))

src = (D / 'index.src.html').read_text(encoding='utf-8')
out = src.replace('{{MATRIX}}', matrix).replace('{{FOOTER}}', footer('', '#main'))
(D / 'index.html').write_text(out, encoding='utf-8', newline='\n')

for name in ('privacy', 'terms'):
    s = (D / f'{name}.src.html').read_text(encoding='utf-8')
    s = s.replace('{{HEADER}}', header_doc()).replace('{{FOOTER}}', footer('index.html', 'index.html', name, note=False))
    (D / f'{name}.html').write_text(s, encoding='utf-8', newline='\n')

for f in ('index.html', 'privacy.html', 'terms.html'):
    t = (D / f).read_text(encoding='utf-8')
    assert '{{' not in t, f
    assert '<script' not in t.lower(), f
    assert not re.search(r'(src|href)="https?://(?!dl\.blanktick\.org|github\.com|www\.gnu\.org|www\.cloudflare\.com)', t), f
print('built')
