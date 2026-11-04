#!/usr/bin/env bash
# blanktick.org deploy runbook. Prereq: `npx wrangler login` done once.
# Account 63f2214f3f2fe2729689f5b3d46ac5ed. Site is a Workers static-assets
# project ("blanktick") configured by ./wrangler.jsonc (assets.directory=web,
# custom_domain routes blanktick.org + www). Redeploy the SITE with:
#     npx wrangler deploy
#
# The 65 MB Windows download lives on R2 at dl.blanktick.org. R2 must be enabled
# once in the dashboard (Cloudflare error 10042 until then). After enabling:
set -euo pipefail
cd "$(dirname "$0")/.."
export CLOUDFLARE_ACCOUNT_ID=63f2214f3f2fe2729689f5b3d46ac5ed MSYS_NO_PATHCONV=1
W="npx --yes wrangler@latest"
BUCKET=blanktick-downloads
ZIP="desktop/build/compose/binaries/main/portable/Blanktick-0.1.3-win-x64.zip"
OBJ="Blanktick-0.1.3-win-x64.zip"
WANT=6EBF28C4451C90F1A3796DAFEA6CFAAC68DDF778373BBE142E58A5B9166FF07B

GOT=$(powershell.exe -NoProfile -Command "(Get-FileHash '$ZIP' -Algorithm SHA256).Hash")
[ "$GOT" = "$WANT" ] || { echo "HASH MISMATCH: $GOT"; exit 1; }
$W r2 bucket create "$BUCKET" || true
$W r2 object put "$BUCKET/$OBJ" --file "$ZIP" --content-type application/zip --remote
MSI="desktop/build/compose/binaries/main/msi/Blanktick-0.1.3.msi"
MSI_OBJ="Blanktick-0.1.3-win-x64.msi"
MSI_WANT=34E8C03390D60FA007C56B4C8ED84483D2851E2D98099407BE57E7A1D2CFDF70
GOT=$(powershell.exe -NoProfile -Command "(Get-FileHash '$MSI' -Algorithm SHA256).Hash")
[ "$GOT" = "$MSI_WANT" ] || { echo "MSI HASH MISMATCH: $GOT"; exit 1; }
$W r2 object put "$BUCKET/$MSI_OBJ" --file "$MSI" --content-type application/x-msi --remote
MCPB="desktop/build/mcpb/Blanktick-0.1.3.mcpb"
MCPB_OBJ="Blanktick-0.1.3.mcpb"
MCPB_WANT=16F85C4888D3E1FDB62CEC0B287BDBCC784E015C8167B9C7F3849BDD42ED39F8
GOT=$(powershell.exe -NoProfile -Command "(Get-FileHash '$MCPB' -Algorithm SHA256).Hash")
[ "$GOT" = "$MCPB_WANT" ] || { echo "MCPB HASH MISMATCH: $GOT"; exit 1; }
$W r2 object put "$BUCKET/$MCPB_OBJ" --file "$MCPB" --content-type application/zip --remote
$W r2 bucket domain add "$BUCKET" --domain dl.blanktick.org --zone-id 71af56df0837f8f6249056a4839f78c3 --min-tls 1.2 -y || true
echo "download live at https://dl.blanktick.org/$MSI_OBJ and https://dl.blanktick.org/$OBJ"
