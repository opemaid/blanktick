#!/usr/bin/env bash
# Microsoft Store package. Builds an UNSIGNED .msix from the jpackage app image;
# the Store signs it on upload, so no code-signing certificate is needed.
#
# Prereqs:
#   ./gradlew :desktop:createDistributable      (app image in desktop/build/compose/binaries/main/app)
#   makeappx/makepri from the Microsoft.Windows.SDK.BuildTools NuGet package,
#   unpacked to $SDK_BIN (default below).
#
# Identity comes from Partner Center > your app > Product identity. Until the
# name is reserved the defaults below build a package that validates but that
# the Store will reject:
#   MSIX_NAME=12345Blanktick.Blanktick MSIX_PUBLISHER="CN=XXXXXXXX-XXXX-..." \
#   MSIX_PUBLISHER_DISPLAY="Blanktick" tools/build-msix.sh
set -euo pipefail
cd "$(dirname "$0")/.."
export MSYS_NO_PATHCONV=1

VERSION=${MSIX_VERSION:-0.1.2.0}          # Store needs the 4th part to be 0
NAME=${MSIX_NAME:-Blanktick.Blanktick}
PUBLISHER=${MSIX_PUBLISHER:-CN=Blanktick}
PUBLISHER_DISPLAY=${MSIX_PUBLISHER_DISPLAY:-Blanktick}
SDK_BIN=${SDK_BIN:-$HOME/tools/winsdk-buildtools/pkg/bin/10.0.28000.0/x64}

APP=desktop/build/compose/binaries/main/app/Blanktick
STAGE=desktop/build/msix/stage
OUT=desktop/build/msix/Blanktick-$VERSION-x64.msix

[ -f "$APP/Blanktick.exe" ] || { echo "no app image at $APP; run ./gradlew :desktop:createDistributable"; exit 1; }

rm -rf "$STAGE" && mkdir -p "$STAGE"
cp -r "$APP"/. "$STAGE"/
cp -r desktop/msix/Assets "$STAGE"/Assets
sed -e "s|@NAME@|$NAME|" -e "s|@PUBLISHER@|$PUBLISHER|" \
    -e "s|@PUBLISHER_DISPLAY@|$PUBLISHER_DISPLAY|" -e "s|@VERSION@|$VERSION|" \
    desktop/msix/AppxManifest.xml > "$STAGE"/AppxManifest.xml

# resources.pri lets Windows pick the scale-200 / targetsize icons.
w() { cygpath -w "$1"; }
"$SDK_BIN/makepri.exe" createconfig /cf "$(w desktop/build/msix/priconfig.xml)" /dq en-US /o >/dev/null
"$SDK_BIN/makepri.exe" new /pr "$(w "$STAGE")" /cf "$(w desktop/build/msix/priconfig.xml)" \
    /of "$(w "$STAGE"/resources.pri)" /mn "$(w "$STAGE"/AppxManifest.xml)" /o >/dev/null

"$SDK_BIN/makeappx.exe" pack /d "$(w "$STAGE")" /p "$(w "$OUT")" /o
powershell.exe -NoProfile -Command "(Get-FileHash '$OUT' -Algorithm SHA256).Hash"
ls -la "$OUT"
