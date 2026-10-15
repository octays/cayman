#!/usr/bin/env bash
set -euo pipefail
if [[ $# != 2 ]]; then echo "Usage: $0 RUST_TARGET PLATFORM" >&2; exit 2; fi
target=$1
platform=$2
case "$platform" in linux-amd64|linux-arm64|darwin-amd64|darwin-arm64|windows-amd64) ;; *) exit 2 ;; esac
name="cayman-$platform"
exe=''
if [[ "$platform" == windows-* ]]; then exe='.exe'; name="$name$exe"; fi
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
mkdir -p dist
cp "target/$target/release/cayman$exe" "$work/original"
binary="$work/$name"
cp "$work/original" "$binary"
if [[ "$platform" == linux-* || "$platform" == windows-* ]]; then
  upx --best --lzma "$binary"
  upx -t "$binary"
  "$binary" --version
  "$binary" send --help >/dev/null
  compression=upx
else
  # Modern Mach-O formats/signatures may not support packing. Never force it.
  if upx --best --lzma "$binary" && upx -t "$binary" && "$binary" --version && "$binary" send --help >/dev/null; then
    compression=upx
  else
    echo "UPX unavailable for this Mach-O binary; keeping original." >&2
    cp "$work/original" "$binary"
    compression=none
  fi
  "$binary" --version
  "$binary" receive --help >/dev/null
fi
cp "$binary" "dist/$name"
chmod 755 "dist/$name"
# Preserve the vendored dependency's license and provenance alongside binaries.
cp vendor/spake2/LICENSE-APACHE dist/LICENSE-spake2
cp vendor/spake2/VENDOR.md dist/VENDOR-spake2.md
(cd dist; if command -v sha256sum >/dev/null; then sha256sum "$name"; else shasum -a 256 "$name"; fi) > "dist/$name.sha256"
printf '%s: target=%s compression=%s\n' "$name" "$target" "$compression"
