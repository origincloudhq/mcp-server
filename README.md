# Origin Cloud MCP server

The hosted [MCP](https://modelcontextprotocol.io) server of
[Origin Cloud](https://origincloud.eu), at `https://mcp.origincloudapis.eu`:
the tools of [origincloudhq/mcp](https://github.com/origincloudhq/mcp), a tool
per method of Origin Cloud's API, served over MCP's Streamable HTTP
transport to any MCP client that connects by URL, with a browser login and
nothing installed.

It is the same library that `origin mcp serve` of the
[`origin` CLI](https://github.com/origincloudhq/cli) serves on your machine:
the same tools, the same instructions, the same defaults. This repository
adds only the transport and the authorization.

## Connecting

Add the server to your MCP client by its URL. Origin Cloud's login doesn't
register clients on the fly: an MCP client logs in as the public client
`origincloud-mcp`, which accepts the redirect `http://localhost:33418/callback`.
In Claude Code:

```sh
claude mcp add --transport http --client-id origincloud-mcp --callback-port 33418 \
  origincloud https://mcp.origincloudapis.eu
```

The client sends you to Origin Cloud's login in your browser the first time.

A connection's options are query parameters of the URL, since many clients
take nothing but a URL:

| Parameter | Value | Default |
|---|---|---|
| `toolsets` | The toolsets to expose, by service, comma-separated or repeated: `pvs,compute` | every toolset |
| `read_only` | `true` exposes only the tools that change nothing: reads, and waiting on operations | `false` |

```text
https://mcp.origincloudapis.eu/?toolsets=pvs,compute&read_only=true
```

A misspelt parameter or toolset is refused with `400`, naming the ones there
are. Tools that delete something, or change it for good, are marked
destructive for your client to confirm.

## How it authorizes

The server is an OAuth 2.1 resource server, as the
[MCP authorization specification](https://modelcontextprotocol.io/specification/latest/basic/authorization)
requires:

1. A request without a bearer token, or with one the server doesn't accept,
   is answered `401` with a `WWW-Authenticate` challenge naming the
   server's protected resource metadata (RFC 9728) and the scope to
   request.
2. The metadata, at `/.well-known/oauth-protected-resource`, names the
   server's canonical URI as its `resource` and Origin Cloud's identity
   provider as its authorization server, where the client logs in.
3. The server accepts a token only if it is a JWT signed with a key of the
   issuer's JWKS (fetched from its OpenID configuration, kept for ten
   minutes, fetched again for a key it doesn't know), issued by the issuer,
   for the server's own audience, and in its lifetime.
4. A tool call reaches the API with an access token the server obtains by
   token exchange (RFC 8693) at the issuer: the caller's token as the
   subject, the server's own confidential client as the requester, the
   API's audience as the target. The exchanged token is kept until shortly
   before it expires, and never past the caller's token. The caller's token
   is never sent anywhere but to the issuer.

A service account's access token works the same way, for agents without a
browser, as long as it was issued for the server's audience.

The server keeps no MCP sessions: each request is answered on its own, so
that any replica can answer any request. Each caller's SDK client is kept
across requests, so that a read shows the caller's earlier writes.

## Running it

```sh
cargo run -- --exchange-client-secret "$SECRET"
```

Every flag can be set by an environment variable instead; `--help` lists
them. The defaults are Origin Cloud's production values.

| Flag | Variable | Default | What it is |
|---|---|---|---|
| `--listen` | `MCP_LISTEN_ADDRESS` | `0.0.0.0:8080` | The MCP endpoint and the metadata |
| `--metrics-listen` | `MCP_METRICS_LISTEN_ADDRESS` | `0.0.0.0:9090` | `/metrics`, `/healthz`, `/readyz` |
| `--resource` | `MCP_RESOURCE` | `https://mcp.origincloudapis.eu` | The canonical URI; the MCP endpoint is its path |
| `--audience` | `MCP_AUDIENCE` | the canonical URI | The audience a token must carry |
| `--issuer` | `MCP_ISSUER` | `https://auth.origincloud.eu/realms/origincloud` | The authorization server |
| `--scopes` | `MCP_SCOPES` | `mcp` | The scopes a client requests, space-separated |
| `--exchange-client-id` | `MCP_EXCHANGE_CLIENT_ID` | `origincloud-mcp-server` | The client the server exchanges tokens as |
| `--exchange-client-secret` | `MCP_EXCHANGE_CLIENT_SECRET` | none, required | Its secret |
| `--api-audience` | `MCP_API_AUDIENCE` | `account` | The audience of an exchanged token |
| `--api-region` | `MCP_API_REGION` | none | The region whose front door the calls go to |
| `--api-endpoint` | `MCP_API_ENDPOINT` | none | One endpoint for every service, such as a fake API |
| `--allowed-hosts` | `MCP_ALLOWED_HOSTS` | none | More `Host` values to answer than the canonical URI's |
| `--unready-on-stop-seconds` | `MCP_UNREADY_ON_STOP_SECONDS` | `0` | How long to report unready on a termination signal before stopping |
| `--drain-seconds` | `MCP_DRAIN_SECONDS` | `65` | How long requests in flight may then take |
| `--log-format` | `MCP_LOG_FORMAT` | `json` | `json` or `text`; `RUST_LOG` filters |

The image is `ghcr.io/origincloudhq/mcp-server`, built for `linux/amd64`
and run as a user without privileges.

### Observing it

- **Logs:** one JSON line per request on standard output, with its method,
  route, status, duration, `x-request-id`, and the token's subject and
  client. Tokens are never logged.
- **Metrics** (Prometheus, on the metrics port):
  `origincloud_http_requests_total`, `origincloud_http_request_duration_seconds`,
  `origincloud_http_requests_in_flight`, `origincloud_mcp_tool_calls_total{tool,outcome}`,
  `origincloud_mcp_token_exchanges_total{outcome}`,
  `origincloud_mcp_auth_refusals_total{reason}` and `origincloud_build_info`.
- **Health:** `/healthz` answers while the process runs; `/readyz` once the
  issuer's configuration has been read, and until a termination signal.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md), and [RELEASING.md](RELEASING.md) for
how a release is made.

## License

Apache License 2.0; see [LICENSE](LICENSE).
