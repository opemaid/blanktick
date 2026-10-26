#!/usr/bin/env bash
# Screenshot every generated page at its exact size into ../ (headless Chrome).
cd "$(dirname "$0")"
C="/c/Program Files/Google/Chrome/Application/chrome.exe"
PROF="$(cygpath -w "$PWD/_prof")"
for f in *.html; do
  n="${f%.html}"
  wh=$(echo "$n" | grep -oE '[0-9]+x[0-9]+$'); w=${wh%x*}; h=${wh#*x}
  out="$(cygpath -w "$PWD/../$n.png")"
  "$C" --headless=new --disable-gpu --hide-scrollbars --force-device-scale-factor=1 \
    --user-data-dir="$PROF" --screenshot="$out" \
    --window-size="$w,$h" "file:///$(cygpath -m "$PWD")/$f" 2>/dev/null
done
rm -rf _prof
