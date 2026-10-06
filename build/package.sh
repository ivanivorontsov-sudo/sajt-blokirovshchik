#!/usr/bin/env bash
# Сборка дистрибутива: self-contained win-x64 single-file publish + zip со скриптами установки.
# Использование: build/package.sh [--no-publish]
set -euo pipefail
cd "$(dirname "$0")/.."
VER=1.0.0
NAME="SiteBlocker-Windows-$VER"
DOTNET="${DOTNET:-/home/box/dotnet/dotnet}"
export DOTNET_CLI_TELEMETRY_OPTOUT=1 DOTNET_NOLOGO=1

if [[ "${1:-}" != "--no-publish" ]]; then
  rm -rf out/publish
  "$DOTNET" publish src/SiteBlocker.App/SiteBlocker.App.csproj -c Release -r win-x64 --self-contained true -o out/publish > out/publish.log 2>&1 \
    || { grep -E "error" out/publish.log | head -20; exit 1; }
fi
test -f out/publish/SiteBlocker.exe

STAGE="dist/$NAME"
rm -rf dist && mkdir -p "$STAGE/app" "$STAGE/recovery"
cp out/publish/SiteBlocker.exe "$STAGE/app/"
cp installer/install.ps1 installer/uninstall.ps1 "installer/Установить.cmd" "installer/Удалить.cmd" "$STAGE/"
cp README.md "$STAGE/"
cp recovery/* "$STAGE/recovery/"

python3 - "$STAGE" "dist/$NAME.zip" <<'PY'
import os, sys, zipfile
stage, out = sys.argv[1], sys.argv[2]
def crlf(b): return b.replace(b'\r\n', b'\n').replace(b'\n', b'\r\n')
for root, _, files in os.walk(stage):
    for f in files:
        p = os.path.join(root, f); ext = os.path.splitext(f)[1].lower()
        if ext == '.reg':
            # .reg (v5.00) с кириллицей должен быть UTF-16 LE.
            b = open(p, 'rb').read()
            if b.startswith(b'\xef\xbb\xbf'): b = b[3:]
            txt = b.decode('utf-8').replace('\r\n','\n').replace('\n','\r\n')
            open(p, 'wb').write(b'\xff\xfe' + txt.encode('utf-16-le'))
        elif ext in ('.ps1', '.txt', '.md', '.cmd'):
            b = open(p, 'rb').read()
            if b.startswith(b'\xef\xbb\xbf'): b = b[3:]
            b = crlf(b)
            if ext in ('.ps1', '.txt'): b = b'\xef\xbb\xbf' + b
            open(p, 'wb').write(b)
base = os.path.dirname(stage)
with zipfile.ZipFile(out, 'w', zipfile.ZIP_DEFLATED, compresslevel=9) as z:
    for root, _, files in os.walk(stage):
        for f in sorted(files):
            p = os.path.join(root, f)
            z.write(p, os.path.relpath(p, base))
print(out, os.path.getsize(out))
PY
