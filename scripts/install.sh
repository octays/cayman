#!/usr/bin/env bash
# Bash 3.2+; Linux/macOS. Installs the latest non-prerelease GitHub release.
set -euo pipefail
fail() { echo "cayman install: $*" >&2; exit 1; }
if [[ $# != 0 ]]; then fail 'Usage: bash install.sh (optional: CAYMAN_INSTALL_DIR=/path/to/bin)'; fi
for tool in curl uname mktemp chmod mv cp mkdir rm; do command -v "$tool" >/dev/null || fail "missing command: $tool"; done
case "$(uname -s)" in Linux) os=linux ;; Darwin) os=darwin ;; *) fail 'supported systems: Linux and macOS (use WSL on Windows)' ;; esac
case "$(uname -m)" in x86_64|amd64) arch=amd64 ;; aarch64|arm64) arch=arm64 ;; *) fail 'supported architectures: amd64 and arm64' ;; esac
if command -v sha256sum >/dev/null; then hash=(sha256sum); elif command -v shasum >/dev/null; then hash=(shasum -a 256); else fail 'sha256sum or shasum is required'; fi
repo=octays/cayman
install_dir=${CAYMAN_INSTALL_DIR:-"$HOME/.local/bin"}
work=$(mktemp -d)
staged=''
cleanup() { rm -rf "$work"; if [[ -n "$staged" ]]; then rm -f "$staged"; fi; }
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
fetch() { curl --fail --silent --show-error --location --retry 3 --connect-timeout 15 --max-time 300 --proto '=https' --proto-redir '=https' "$@"; }
# Resolve latest once so an intervening release cannot mix binary and checksum.
url=$(fetch -o /dev/null -w '%{url_effective}' "https://github.com/$repo/releases/latest")
prefix="https://github.com/$repo/releases/tag/"
[[ "$url" == "$prefix"* ]] || fail 'no latest release found'
tag=${url#"$prefix"}
[[ "$tag" =~ ^v[0-9][A-Za-z0-9._+-]*$ ]] || fail "unexpected release tag: $tag"
name="cayman-$os-$arch"
asset="$name"
base="https://github.com/$repo/releases/download/$tag"
echo "Downloading $tag ($os/$arch)..."
fetch -o "$work/$asset" "$base/$asset"
fetch -o "$work/checksum" "$base/$asset.sha256"
read -r expected filename < "$work/checksum"
[[ "$expected" =~ ^[a-fA-F0-9]{64}$ && "$filename" == "$asset" ]] || fail 'invalid checksum file'
actual=$("${hash[@]}" "$work/$asset")
[[ "${actual%% *}" == "$expected" ]] || fail 'SHA-256 mismatch; installed binary was not changed'
[[ -s "$work/$asset" ]] || fail 'empty executable'
chmod 755 "$work/$asset"
"$work/$asset" --version
mkdir -p "$install_dir"
staged=$(mktemp "$install_dir/.cayman-install.XXXXXX")
cp "$work/$asset" "$staged"
chmod 755 "$staged"
[[ ! -d "$install_dir/cayman" ]] || fail 'destination is a directory'
mv -f "$staged" "$install_dir/cayman"
staged=''
echo "Installed $tag to $install_dir/cayman"
case ":$PATH:" in *":$install_dir:"*) ;; *) printf 'Add to your shell profile: export PATH=%q:$PATH\n' "$install_dir" ;; esac
