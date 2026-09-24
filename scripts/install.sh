#!/bin/sh
# Installs MCPBytes Vault from the latest GitHub release, for the current user:
#   curl -fsSL https://github.com/MCPBytes/mcpbytes-vault/releases/latest/download/install.sh | sh
# Options go to `mcpbytes-vault install`:  ... | sh -s -- --store file
# It downloads this platform's archive, checks it against the release's SHA256SUMS.txt, unpacks it
# in a temporary folder and runs `mcpbytes-vault install`, which copies the program into place.
set -eu

release="${MCPBYTES_VAULT_RELEASE_URL:-https://github.com/MCPBytes/mcpbytes-vault/releases/latest/download}"
case "$release" in https://*) proto="=https" ;; *) proto="=http,https" ;; esac  # plain http only for a local test mirror

case "$(uname -s) $(uname -m)" in
  "Linux x86_64") platform=linux-x64 ;;
  "Darwin arm64") platform=macos-arm64 ;;
  *)
    echo "mcpbytes-vault: no release build for $(uname -s) $(uname -m); build it from source:" >&2
    echo "  https://github.com/MCPBytes/mcpbytes-vault#install" >&2
    exit 1 ;;
esac
archive="mcpbytes-vault-$platform.tar.gz"

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT INT TERM
for file in "$archive" SHA256SUMS.txt; do
  curl --proto "$proto" --tlsv1.2 -fsSL "$release/$file" -o "$tmp/$file"
done

expected=$(awk -v name="$archive" '$2 == name { print $1 }' "$tmp/SHA256SUMS.txt")
if command -v sha256sum >/dev/null 2>&1; then
  actual=$(sha256sum "$tmp/$archive" | cut -d ' ' -f 1)
else
  actual=$(shasum -a 256 "$tmp/$archive" | cut -d ' ' -f 1)
fi
if [ -z "$expected" ] || [ "$expected" != "$actual" ]; then
  echo "mcpbytes-vault: $archive does not match SHA256SUMS.txt; nothing was installed" >&2
  exit 1
fi

tar -xzf "$tmp/$archive" -C "$tmp"
"$tmp"/mcpbytes-vault-*/mcpbytes-vault install "$@"
