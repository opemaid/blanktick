# Release checklist

Blocking items before Blanktick is published. Each one is here because it is *not*
done, not as a reminder that it might be.

## 1. LICENSE file is missing — BLOCKER

The project is **AGPL-3.0**. The `LICENSE` file does not exist yet, because the
canonical text could not be fetched from this machine and reproducing a legal
document from memory is not acceptable — a single altered clause in a licence is
worse than having none.

Do one of:

```bash
curl -L https://www.gnu.org/licenses/agpl-3.0.txt -o LICENSE
```

or, when creating the GitHub repository, choose **GNU Affero General Public
License v3.0** from the licence dropdown and let GitHub write the file.

Then add the standard notice to `README.md` and keep the per-file headers short.

**Until `LICENSE` contains the verbatim AGPL-3.0 text, the repository is
"source available" and not licensed open source.** Nobody has permission to use
it, which is the default in the absence of a licence.

## 2. Binaries are unsigned

Decided: ship unsigned, publish SHA-256 checksums, and explain the SmartScreen
warning plainly on the download page rather than pretending it will not appear.

A non-trivial number of non-technical users — the people this product is written
for — will stop at "Windows protected your PC". That is a known, accepted cost of
the current approach and should be revisited before any real launch.

## 3. Installer (MSI) and portable build — RESOLVED 2026-10-23

WiX is now available and `gradlew :desktop:packageMsi` produces a per-user MSI
(no admin rights, Start-menu entry, Blanktick icon from `desktop/packaging/blanktick.ico`).
The site leads with the MSI; the ZIP below remains as the portable option.
Historical note follows.

`packageMsi` requires the WiX Toolset, which is not installed. The shipping
artefact is a ZIP of `createDistributable` output: a folder containing
`Blanktick.exe` and a bundled JRE. It runs from anywhere and needs no installation,
which is arguably better for a tool people are meant to distrust — but it is not
what most Windows users expect.

To produce a real installer: install WiX 3.x, then `gradlew :desktop:packageMsi`.

## 4. Threat data is synthetic

`manifest.txt` carries `synthetic=true`. Both apps detect this and say so on
screen, so nothing is claimed falsely — but the password and link checks are not
meaningful until real corpora are built:

```bash
python tools/build_intel.py --passwords pwned-top2m.txt --domains hosts.txt
```

## 5. macOS and Linux collectors are unrun

`MacCollector` has never executed on a Mac. `LinuxCollector` has only run under
WSL, which is not a desktop session. Both fail to `null` (reported as "not
checkable") rather than guessing, so they are safe to ship — but the download
page must not imply tested macOS/Linux support.

**The binary-resolution guard is now the exception, and only on Linux.** It was
the one part where being unrun was a security problem rather than a coverage
one: it decides whether Blanktick reads the operating system or reads whatever an
attacker put on `PATH`, and it depends on filesystem ownership that varies by
machine. It has now been executed against the real compiled Kotlin on a real
POSIX filesystem (Ubuntu 24.04 under WSL, `tools/LinuxResolveCheck.java`): all
seven installed tools resolved to root-owned paths, a binary planted in a
user-writable directory was refused, a root-owned binary under a world-writable
parent was refused, and with a hijack directory first on `PATH` the shell's own
`command -v id` returned the planted copy while Blanktick returned `/usr/bin/id`.

**macOS remains unverified**, and there is no Mac here to change that. What can
be said precisely: a wrong directory in the macOS trusted list makes a tool fail
to resolve, which reports as *not checkable* — it cannot make a planted binary
acceptable, because ownership is now checked against the filesystem at run time
rather than inferred from the path, and that check is the part verified above.
So the residual macOS risk is silently reduced coverage, not a forged pass.

Anyone with a Mac can settle it in one command: `Blanktick --tools` prints each tool,
where it resolved, and what to compare it against.

## 6. Screenshots must not come from a real machine

`.gitignore` excludes `docs/shots/` for this reason: a full-screen capture of a
working scan shows the operator's taskbar, installed apps, location, local
administrator names and DNS resolvers. Documentation screenshots must come from
a clean VM or be synthetic, and go in `docs/shots/public/`.

## 7. The marketing site fetches webfonts from Google and Fontshare

`web/index.html` loads:

- `https://fonts.googleapis.com/css2?family=JetBrains+Mono`
- `https://api.fontshare.com/v2/css?f[]=clash-display&f[]=switzer`

For a product whose entire claim is *"this never phones home"*, the page making
that claim phones home to two third parties before it finishes rendering. Google
Fonts in particular hands the visitor's IP to Google on every page load, which a
German court has already ruled a GDPR violation.

It is not a bug in the app, and no user data is at risk. It is a contradiction
sitting on the front page, and the first sceptical reader will open the network
tab and find it — on the one site that invites them to.

**Fix:** self-host the two font files from `web/fonts/`, or drop to the system
stack the desktop app already uses. One decision, and the site then makes zero
external requests.

## 8. The site is invisible below the hero without JavaScript — partly fixed

`[data-reveal]` elements start at `opacity: 0` and are revealed by an
IntersectionObserver. If the observer never runs, every section below the hero
stays permanently invisible — and the page does not look broken, it looks like a
one-screen site.

I previously said a `<noscript>` fallback covered this. **That was wrong**: the
`<noscript>` block only loads a webfont stylesheet. There was no fallback at all.

Now fixed two ways: the hidden state is applied by a script (`.js-reveal`), so no
JS means no hiding, and an eight-second timer reveals anything the observer
missed. **Not yet visually confirmed** — repeated headless captures still showed
nothing below the hero, which may be the harness or may mean something else is
collapsing those sections. Open it in a real browser and scroll before trusting
this item.
