#!/usr/bin/env bash
#
# Moves the server to the newest MCP tools: the origincloud-mcp dependency to
# the head of origincloudhq/mcp's main, and the SDK dependency to the
# origincloudhq/sdk-rust commit that one is built on. The update workflow
# (.github/workflows/update.yml) runs it daily and when origincloudhq/mcp's
# main moves; run it by hand the same way.
#
# The server has no tools of its own: a method added to the API reaches it
# through the tools' library, and this script is all it takes. The SDK moves
# with the tools because the server hands them the SDK's `Client`, so both
# must be one crate.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
readonly ROOT
readonly MCP_REPOSITORY="https://github.com/origincloudhq/mcp.git"

cd "${ROOT}"

mcp="$(git ls-remote "${MCP_REPOSITORY}" refs/heads/main | cut -f1)"
[[ "${mcp}" =~ ^[0-9a-f]{40}$ ]] || { echo "no main branch in ${MCP_REPOSITORY}" >&2; exit 1; }
sdk="$(scripts/check.sh --sdk-of "${mcp}")"

# Both revisions move in Cargo.toml before the lock moves, in one `cargo
# update`: moving the MCP crate alone would have the lock hold the SDK's
# crates at two commits, which `cargo update -p` can't then name.
packages=()
if ! grep -qF "rev = \"${mcp}\"" Cargo.toml; then
  sed -i -E "s|(git = \"https://github.com/origincloudhq/mcp\", rev = \")[0-9a-f]{40}(\")|\1${mcp}\2|" Cargo.toml
  packages+=(-p origincloud-mcp)
fi
if ! grep -qF "rev = \"${sdk}\"" Cargo.toml; then
  sed -i -E "s|(git = \"https://github.com/origincloudhq/sdk-rust\", rev = \")[0-9a-f]{40}(\")|\1${sdk}\2|" Cargo.toml
  while read -r crate; do
    packages+=(-p "${crate}")
  done < <(grep -oE '^[a-z0-9-]+ = \{ git = "https://github.com/origincloudhq/sdk-rust"' Cargo.toml | cut -d' ' -f1)
fi
if [[ "${#packages[@]}" -gt 0 ]]; then
  cargo update --quiet "${packages[@]}"
fi
# Adds what Cargo.toml needs and the lock doesn't hold yet; it moves no other
# dependency.
cargo update --quiet --workspace

echo "origincloudhq/mcp@${mcp:0:12}, origincloudhq/sdk-rust@${sdk:0:12}"
scripts/check.sh
