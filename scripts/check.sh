#!/usr/bin/env bash
#
# Checks that Cargo.toml pins every crate of origincloudhq/sdk-rust at the
# commit the pinned origincloudhq/mcp commit is built on: the server hands
# the tools the SDK's `Client`, so a second SDK commit wouldn't build, or
# worse, would build two `Client`s. CI runs it on every pull request.
#
#   scripts/check.sh                 # check Cargo.toml
#   scripts/check.sh --sdk-of <rev>  # print the SDK commit an MCP commit pins
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
readonly ROOT
readonly MCP_REPOSITORY="https://github.com/origincloudhq/mcp.git"

cd "${ROOT}"

# The SDK commit the MCP commit $1 pins in its Cargo.toml.
sdk_of() {
  local tmp sdk
  tmp="$(mktemp -d)"
  # shellcheck disable=SC2064 # expanded now, on purpose
  trap "rm -rf '${tmp}'" RETURN
  git init --quiet "${tmp}"
  git -C "${tmp}" fetch --quiet --depth 1 "${MCP_REPOSITORY}" "$1"
  sdk="$(git -C "${tmp}" show FETCH_HEAD:Cargo.toml \
    | grep -m1 -oE 'sdk-rust", rev = "[0-9a-f]{40}"' | grep -oE '[0-9a-f]{40}')" || true
  [[ "${sdk}" =~ ^[0-9a-f]{40}$ ]] || { echo "the MCP commit ${1:0:12} pins no commit of origincloudhq/sdk-rust" >&2; return 1; }
  echo "${sdk}"
}

if [[ "${1:-}" == --sdk-of ]]; then
  sdk_of "$2"
  exit 0
fi

mcp="$(grep -oE 'origincloudhq/mcp", rev = "[0-9a-f]{40}"' Cargo.toml | grep -oE '[0-9a-f]{40}')"
want="$(sdk_of "${mcp}")"
failed=0
while read -r crate rev; do
  if [[ "${rev}" != "${want}" ]]; then
    echo "Cargo.toml pins ${crate} at origincloudhq/sdk-rust@${rev:0:12}, but origincloudhq/mcp@${mcp:0:12} is built on ${want:0:12}: run scripts/update.sh" >&2
    failed=1
  fi
done < <(sed -nE 's/^([a-z0-9-]+) = \{ git = "https:\/\/github.com\/origincloudhq\/sdk-rust", rev = "([0-9a-f]{40})".*/\1 \2/p' Cargo.toml)
[[ "${failed}" -eq 0 ]] || exit 1
echo "origincloudhq/mcp@${mcp:0:12} and the SDK at ${want:0:12} agree"
