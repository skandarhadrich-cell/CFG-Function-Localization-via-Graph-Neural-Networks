#!/usr/bin/env bash
# Install the Arrodes command into a directory on PATH.
#
# Usage:
#   ./scripts/install_arrodes.sh
#   ./scripts/install_arrodes.sh /usr/local/bin

set -euo pipefail

script_path="$(readlink -f -- "${BASH_SOURCE[0]}")"
repo_root="$(cd -- "$(dirname -- "$script_path")/.." && pwd)"
install_dir="${1:-$HOME/.local/bin}"

mkdir -p "$install_dir"
ln -sfn "$repo_root/bin/Arrodes" "$install_dir/Arrodes"
chmod +x "$repo_root/bin/Arrodes"

printf 'installed %s -> %s\n' "$install_dir/Arrodes" "$repo_root/bin/Arrodes"
if [[ ":$PATH:" != *":$install_dir:"* ]]; then
    printf 'warning: %s is not on PATH\n' "$install_dir" >&2
fi
