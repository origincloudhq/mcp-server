# Contributing

Thank you for helping improve Origin Cloud's hosted MCP server.

## Issues

Open an issue for anything that is wrong, unclear or missing: a client that
can't connect or log in, a refusal that doesn't say why, a header the
server gets wrong. Say which client it is, and include the requests and
answers where you can, with tokens and account details removed.

A tool that behaves differently from its description is the tools'
library's: open it at [origincloudhq/mcp](https://github.com/origincloudhq/mcp).

To report a security vulnerability, don't open an issue: use **Report a
vulnerability** on this repository's Security tab, which reaches us
privately.

## Pull requests

Pull requests are reviewed and merged here. For anything larger than a small
fix, open an issue first, so that we can agree on the change before you spend
time on it. CI must pass: `scripts/check.sh`, `cargo fmt --check`,
`cargo clippy --all-targets -- -D warnings`, `cargo test`, `shellcheck
scripts/*.sh`, and the image build.

## How it is built

- `src/lib.rs` is the server: the MCP endpoint, the protected resource
  metadata, and the stop on a termination signal. `src/main.rs` reads the
  configuration (`src/config.rs`) and runs it.
- `src/auth/` checks bearer tokens against the issuer's keys and builds the
  `WWW-Authenticate` challenge; `src/exchange.rs` exchanges a caller's token
  for one the API accepts, and keeps it until it is due.
- `src/clients.rs` holds each caller's SDK client; `src/session.rs` serves
  one request with the library's server, its tool calls going through the
  caller's client.
- `src/options.rs` reads a connection's options from the URL's query.
- `tests/end_to_end.rs` runs the server between a fake authorization server
  and the SDK's fake API (`tests/common/`), through an MCP client.

The server has no tools of its own. A method added to the API reaches it
through the library: the API's definitions generate the
[Rust SDK](https://github.com/origincloudhq/sdk-rust), the SDK generates the
tools in origincloudhq/mcp, and `scripts/update.sh` moves this server to the
head of that repository's `main` and to the SDK commit the tools are built
on. The update workflow (`.github/workflows/update.yml`) runs it when the
library's `main` moves, and daily, and opens a pull request; once CI passes,
`merge-update.yml` merges it unless someone added commits to it, and
`release.yml` publishes the image of the merge. Both use a GitHub App's
token (the variable `REGENERATE_APP_ID` and the secret
`REGENERATE_APP_PRIVATE_KEY`); without it, the pull request is merged by
hand.

The tools and the server must use one SDK commit, since the server hands
the tools the SDK's `Client`: `scripts/check.sh` fails when `Cargo.toml`
pins another than the library's.
