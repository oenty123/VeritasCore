#!/usr/bin/env bash
# Rebuild the Nexus Security Pro extension and produce a .vsix.
#
# Preferred path (needs npm + network): type-checks against @types/vscode and
# packages with @vscode/vsce. Fallback path (offline): transpiles with tsc
# --noCheck and assembles the .vsix by hand.
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
EXT="$HERE/extension"
VERSION="1.0.0"
VSIX="$HERE/veritas-core-$VERSION.vsix"

cd "$EXT"

if command -v npm >/dev/null && npm ping >/dev/null 2>&1; then
  echo "==> Preferred build (npm + vsce)"
  npm install
  npm run compile
  npx @vscode/vsce package -o "$VSIX"
  echo "==> Built (signed-layout) $VSIX"
  exit 0
fi

echo "==> Offline build (tsc --noCheck + manual .vsix assembly)"
command -v tsc >/dev/null || npm install -g typescript || { echo "need typescript"; exit 1; }

rm -rf out && mkdir -p out
# transpile from a clean dir so a project tsconfig doesn't conflict with file args
TMP="$(mktemp -d)"; cp src/*.ts "$TMP/"
( cd "$TMP" && tsc *.ts --noCheck --outDir out --module commonjs --target ES2020 \
    --skipLibCheck --moduleResolution node --ignoreDeprecations 6.0 )
cp "$TMP"/out/*.js out/
for f in out/*.js; do node --check "$f"; done
echo "    JS syntax OK"

STAGE="$(mktemp -d)"; mkdir -p "$STAGE/extension"
cp -r out "$STAGE/extension/out"
cp package.json README.md "$STAGE/extension/"
[ -f "$HERE/veritas_core.py" ] && cp "$HERE/veritas_core.py" "$STAGE/extension/"

cat > "$STAGE/[Content_Types].xml" <<'XML'
<?xml version="1.0" encoding="utf-8"?>
<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">
  <Default Extension="json" ContentType="application/json"/>
  <Default Extension="js" ContentType="application/javascript"/>
  <Default Extension="md" ContentType="text/markdown"/>
  <Default Extension="py" ContentType="text/x-python"/>
  <Default Extension="vsixmanifest" ContentType="text/xml"/>
  <Default Extension="png" ContentType="image/png"/>
  <Default Extension="txt" ContentType="text/plain"/>
</Types>
XML

cat > "$STAGE/extension.vsixmanifest" <<XML
<?xml version="1.0" encoding="utf-8"?>
<PackageManifest Version="2.0.0" xmlns="http://schemas.microsoft.com/developer/vsx-schema/2011" xmlns:d="http://schemas.microsoft.com/developer/vsx-schema-design/2011">
  <Metadata>
    <Identity Language="en-US" Id="veritas-core" Version="$VERSION" Publisher="veritas-core"/>
    <DisplayName>Nexus Security Pro</DisplayName>
    <Description xml:space="preserve">Contract-oriented security gate for Python.</Description>
    <Tags>python,security,linter,sast,guard</Tags>
    <Categories>Linters,Programming Languages</Categories>
    <GalleryFlags>Public</GalleryFlags>
    <Properties><Property Id="Microsoft.VisualStudio.Code.Engine" Value="^1.80.0"/></Properties>
  </Metadata>
  <Installation><InstallationTarget Id="Microsoft.VisualStudio.Code"/></Installation>
  <Dependencies/>
  <Assets>
    <Asset Type="Microsoft.VisualStudio.Code.Manifest" Path="extension/package.json" Addressable="true"/>
    <Asset Type="Microsoft.VisualStudio.Services.Content.Details" Path="extension/README.md" Addressable="true"/>
  </Assets>
</PackageManifest>
XML

( cd "$STAGE" && rm -f "$VSIX" && zip -rq "$VSIX" "[Content_Types].xml" extension.vsixmanifest extension )
echo "==> Built (offline) $VSIX"
echo "    Install: code --install-extension $VSIX"
