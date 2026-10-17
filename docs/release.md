# Release runbook

How a Blanktick release is cut, what the automation does, and what it
deliberately leaves to a human. This is the operational companion to
`RELEASE-CHECKLIST.md` (which lists the blockers before any *public* launch);
read that first.

## What a release produces

A Windows MSI installer for Blanktick, published as a GitHub Release with a
SHA-256 checksum alongside it. The MSI is a per-user install (no administrator
rights, no UAC prompt) and carries the severed-tick icon.

The MSI is **unsigned** — see [Signing gap](#the-signing-gap) below. That is a
known, accepted state for now, not an oversight.

## How to cut a release

1. **Make sure the branch is releasable.** CI (`.github/workflows/ci.yml`) is
   green on the commit you intend to tag: `:core:test` and `:desktop:test`
   pass, including the cross-language intel corpus checks.

2. **Run the manual QA checklist** below. The automation does not do any of it.

3. **Bump the version** in `desktop/build.gradle.kts`. In
   `compose.desktop { application { nativeDistributions { ... } } }`:

   ```kotlin
   packageVersion = "0.1.0"   // <- bump this, e.g. to "0.2.0"
   ```

   Keep it to `MAJOR.MINOR.PATCH`. Note the macOS block overrides its own
   `packageVersion = "1.0.0"` (macOS installers require a major > 0); that is
   intentional and unrelated to the Windows MSI version. Commit this change.

4. **Tag and push.** The tag must match `v*` and should carry the same version:

   ```bash
   git tag v0.2.0
   git push origin v0.2.0
   ```

   Pushing the tag triggers `.github/workflows/release.yml`. The tag name
   (`v0.2.0`) and the in-MSI `packageVersion` (`0.2.0`) are maintained
   separately — keep them in step by hand.

5. **Watch the workflow**, then check the drafted/published Release has the
   `.msi` and `.msi.sha256` attached and the MSI installs on a clean Windows
   VM.

## What the release workflow does

`.github/workflows/release.yml`, on a `v*` tag push, on `windows-latest`:

1. Checks out the repo.
2. Sets up JDK 17 (temurin) and Python 3.12 — same as CI.
3. **Builds the intel bundle** with the *same* step CI uses:
   `python tools/build_intel.py --demo --drivers tools/seeds/driver-hashes-test.txt --out desktop/src/main/resources/intel`.
   This is the **synthetic/test** corpus. See
   [Intel data is synthetic](#intel-data-is-synthetic) — this must change before
   a real public release.
4. **Builds the MSI**: `./gradlew :desktop:packageMsi`. This is the Compose
   Desktop task that runs `jpackage` against the `targetFormats(Msi, …)`
   configuration. It is `finalizedBy assertNoNetworkBytecode`, so the offline
   guarantee is re-verified as part of packaging. (The ProGuard-minified
   variant is `packageReleaseMsi`; the workflow uses plain `packageMsi`.)
   `jpackage` needs the WiX Toolset v3, which is preinstalled on the
   `windows-latest` image.
5. **Locates the MSI** under `desktop/build/compose/binaries/main/msi/` and
   writes a `.sha256` next to it.
6. **Creates the GitHub Release** for the tag (via
   `softprops/action-gh-release`) and uploads the `.msi` and `.msi.sha256`.

## The signing gap

`jpackage` emits an MSI with **no Authenticode signature**. Consequences on a
fresh machine:

- Windows SmartScreen shows *"Windows protected your PC" / "Unknown publisher"*;
  the user must click **More info → Run anyway**.
- The installer has no "Digital Signatures" tab.

Current decision (`RELEASE-CHECKLIST.md` item 2): **ship unsigned, publish
SHA-256 checksums, and explain the SmartScreen warning plainly on the download
page** rather than pretend it will not appear. A non-trivial share of the
non-technical users this product targets will stop at that warning — an accepted
cost that should be revisited before any real launch.

The release workflow does **not** sign, on purpose: a build server holding a
signing key is a liability, and buying/provisioning a certificate is a paid step
with identity-verification that belongs to a person.

### Options for closing it, when the time comes

- **Azure Trusted Signing** — signs via a cloud service, so no certificate or
  private key is stored in CI. Add `azure/trusted-signing-action` after the MSI
  build, authenticated with an OIDC/federated identity (`azure/login`).
  Lowest key-handling risk; cheapest ongoing; recommended first option.
- **Purchased OV/EV code-signing certificate + `SignTool`** — store the PFX as a
  base64 secret, decode at runtime, then
  `signtool sign /fd SHA256 /tr <timestamp-url> /td SHA256 /f cert.pfx /p "$PW" *.msi`.
  An **EV** cert gives immediate SmartScreen reputation but normally lives on an
  HSM/USB token, which usually means an attended or self-hosted runner. An
  **OV** cert builds reputation over time.
- After signing, verify: `signtool verify /pa /v Blanktick-*.msi`.

The workflow's top-of-file comment block holds concrete snippets for each; drop
the signing step in after "Build the MSI installer" and before the release is
created.

## Intel data is synthetic

The release workflow currently bundles the **same synthetic corpus as CI**
(`--demo` + the committed BYOVD test seed). That yields a working, installable
MSI, but `manifest.txt` will carry `synthetic=true`, and both apps detect that
and tell the user on screen that the password/link/driver checks are not yet
meaningful (`RELEASE-CHECKLIST.md` item 4).

Before a real public release, replace the "Build intel bundle" step with a build
of the real corpus:

```bash
python tools/fetch_loldrivers.py --out tools/seeds/driver-hashes.txt
python tools/build_intel.py \
  --passwords pwned-top2m.txt --domains hosts.txt \
  --drivers tools/seeds/driver-hashes.txt \
  --out desktop/src/main/resources/intel
```

(Confirm the exact `fetch_loldrivers.py` / `build_intel.py` flags against those
tools; the password/domain source lists are supplied by you, not committed.)

## Manual QA checklist (before tagging)

The workflow builds and publishes; it does not judge quality. Do these by hand
on the commit you are about to tag:

- [ ] CI is green on the exact commit (core + desktop tests).
- [ ] `packageVersion` in `desktop/build.gradle.kts` is bumped and committed,
      and matches the `vX.Y.Z` tag you will push.
- [ ] A locally built MSI (`./gradlew :desktop:packageMsi`) **installs on a
      clean Windows VM** and launches — not only on your dev machine.
- [ ] The app runs a scan end-to-end and the About screen shows the new version.
- [ ] If the bundled intel is still synthetic, the app visibly says so and you
      accept shipping it that way (otherwise swap in the real corpus first).
- [ ] The offline guarantee holds: `./gradlew :desktop:assertNoNetworkBytecode`
      passes (it also runs automatically as part of `packageMsi`).
- [ ] No real-machine screenshots are being published
      (`RELEASE-CHECKLIST.md` item 6) — captures come from a clean VM or are
      synthetic.
- [ ] The download page explains the unsigned/SmartScreen warning and links the
      published SHA-256 checksum.
- [ ] `RELEASE-CHECKLIST.md` blockers relevant to a *public* launch (LICENSE
      text present, etc.) are resolved if this is a public release.
