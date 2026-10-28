#!/usr/bin/env bash
# Claude Desktop extension. Bundles the jpackage app image with the manifest in
# integrations/claude-desktop into a one-click .mcpb: double-click it (or drag it
# onto Claude Desktop > Settings > Extensions) and Blanktick's MCP server is
# installed with no config file to edit.
#
# Prereqs:
#   ./gradlew :desktop:createDistributable      (app image in desktop/build/compose/binaries/main/app)
#   Node, for npx @anthropic-ai/mcpb
set -euo pipefail
cd "$(dirname "$0")/.."
export MSYS_NO_PATHCONV=1

APP=desktop/build/compose/binaries/main/app/Blanktick
STAGE=desktop/build/mcpb/stage
VERSION=$(python -c "import json;print(json.load(open('integrations/claude-desktop/manifest.json'))['version'])")
OUT=desktop/build/mcpb/Blanktick-$VERSION.mcpb

[ -f "$APP/Blanktick.exe" ] || { echo "no app image at $APP; run ./gradlew :desktop:createDistributable"; exit 1; }

rm -rf "$STAGE" && mkdir -p "$STAGE/server"
cp -r "$APP"/. "$STAGE"/server/
cp integrations/claude-desktop/manifest.json integrations/claude-desktop/icon.png "$STAGE"/

npx --yes @anthropic-ai/mcpb validate "$STAGE/manifest.json"
npx --yes @anthropic-ai/mcpb pack "$STAGE" "$OUT"
powershell.exe -NoProfile -Command "(Get-FileHash '$OUT' -Algorithm SHA256).Hash"
ls -la "$OUT"
