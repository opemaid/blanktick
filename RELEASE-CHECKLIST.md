# Release checklist

Blocking items before Mume is published. Each one is here because it is *not*
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

## 3. No installer, only a portable build

`packageMsi` requires the WiX Toolset, which is not installed. The shipping
artefact is a ZIP of `createDistributable` output: a folder containing
`Mume.exe` and a bundled JRE. It runs from anywhere and needs no installation,
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

## 6. Screenshots must not come from a real machine

`.gitignore` excludes `docs/shots/` for this reason: a full-screen capture of a
working scan shows the operator's taskbar, installed apps, location, local
administrator names and DNS resolvers. Documentation screenshots must come from
a clean VM or be synthetic, and go in `docs/shots/public/`.
