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
(The server accepts a token of any client, so a client that registers itself
works as well.) In Claude Code:

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
| `service_account` | A service account to act as, by its full name: `//iam.origincloudapis.eu/organizations/{organization}/serviceAccounts/{service_account}` (see [Acting as a service account](#acting-as-a-service-account)) | you, with your own roles |

```text
https://mcp.origincloudapis.eu/?toolsets=pvs,compute&read_only=true
```

A misspelt parameter or toolset is refused with `400`, naming the ones there
are. Tools that delete something, or change it for good, are marked
destructive for your client to confirm.

`toolsets` and `read_only` only choose which tools your client sees. The
API decides what a call may do, by the roles of whoever the call is made
as.

### Acting as a service account

To give an agent less than your own rights, connect it as a service account
that holds only the roles the agent needs, such as a viewer role on one
project:

```text
https://mcp.origincloudapis.eu/?service_account=//iam.origincloudapis.eu/organizations/{organization}/serviceAccounts/{service_account}
```

You still log in as yourself. The server then asks the STS for the service
account's token instead of yours (token exchange naming the account in
`service_account`), and every tool call reaches the API with that token.
The API enforces the account's roles: a write the account may not make is
refused `403` by the API, and the tool returns that error. The audit log
names the service account as the principal, with you and this server as
the parties acting for it.

- You need `roles/iam.service-account-token-creator`
  (`iam.serviceAccounts.getAccessToken`) in the account's organisation. The
  account may be `EXTERNAL` or `WORKLOAD`.
- Without that binding, or if the account doesn't exist or isn't active, the
  connection's first request is answered `403` with
  `WWW-Authenticate: Bearer error="insufficient_scope"` and a description
  naming the account and the role. The STS doesn't say which of these it
  was, so the server can't say either. Your own token is never used in its
  place. A refusal is remembered for thirty seconds, like any other.
- Only a person can impersonate a service account: a service account's own
  token on such a connection is refused the same way.
- The value must be a service account's full name in its one spelling,
  URL-encoded or not. Anything else, an empty value, or the parameter given
  twice, is refused with `400` before the STS is asked.
- If a binding is removed, the next exchange is refused. A token already
  issued stays valid until it expires, at most the STS's token lifetime, and
  never past your own token.

The same parameter names the account at the STS for the CLI's
`--impersonate-service-account` and the SDKs' impersonation option.

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
3. The server accepts a token only if it was issued for the server's own
   audience, is in its lifetime, and comes from a trusted issuer:
   - **The realm people sign in at.** The token must be a JWT signed with a
     key of the realm's JWKS (fetched from its OpenID configuration, kept
     for ten minutes, fetched again for a key it doesn't know) and issued by
     the realm. Any client's token is accepted, if it is a person's access
     token as the STS requires it (type `Bearer`, a user id as the subject,
     and the `email`, `email_verified`, `name`, `given_name` and
     `family_name` claims): anything else is refused early.
   - **A zone's security token service (STS)**, whose tokens name it as
     `origincloud:sts:<zone>`, such as a service account's token for this
     server's audience. Its issuer, audience and lifetime are checked here;
     its signature is checked by the STS itself when the server exchanges the
     token (see 5), which the server does before it serves the request: a
     token the STS doesn't accept is refused with `401`. The STS signs EdDSA
     and names its key, so a token that doesn't is refused without asking it.
     Such exchanges of tokens nobody has checked are limited (a few at once,
     a few dozen a second); past the limit the request is answered `503` with
     `Retry-After`, counted as `unavailable`. A token the STS accepted once,
     and a realm's token, aren't limited.

   A token is refused if it is longer than 16 KiB, expired, or expires more
   than seven days ahead.

   A token of any other issuer is refused. `--allowed-clients` optionally
   restricts the server to tokens issued to some clients (`azp`); it is empty
   by default. A token of another client, or one that names none, such as an
   STS's, is then answered `403` with
   `WWW-Authenticate: Bearer error="insufficient_scope"` (RFC 6750, section
   3.1), before it is ever exchanged.
4. A refused token is counted by reason in
   `origincloud_mcp_auth_refusals_total{reason}`. A token the STS refused for
   the service account the connection names is answered `403` and counted
   as `impersonation` (see
   [Acting as a service account](#acting-as-a-service-account)).
5. A tool call reaches the API with an access token the STS issues by token
   exchange (RFC 8693): the caller's token as the `subject_token`, and this
   server's own credential as the `actor_token`, an assertion signed with the
   server's workload certificate of the zone's certificate authority (see
   below). The issued token keeps the caller as its subject and names this
   server as the party acting for them (`act`). On a connection naming a
   service account the exchange names it too (`service_account`), and the
   issued token is the account's, the caller in its `act` with this server
   nested inside. Such a token is held apart from the caller's own, and
   such a connection's token is exchanged before its first request is
   served, whoever issued it. It is kept until shortly
   before it expires, and never past the caller's token; a token the STS
   refused (`invalid_grant`, and nothing else) isn't asked about again for
   thirty seconds, unless it isn't valid yet; callers presenting the same
   token at once share one exchange. Any other error of the STS (`invalid_request`,
   `invalid_client`, `invalid_target`, ...) is this server's own fault, not
   the token's: it is logged as an error, answered `503`, and not remembered.
   Callers of a tool are told no more than that the token couldn't be
   exchanged; the detail is in the logs. The caller's token is
   never sent anywhere but to the STS that exchanges it.

The hosted server is for people signing in through their MCP client, and for
service accounts that obtain a token for this server's audience. An agent that
can't reach it runs `origin mcp serve` of the
[`origin` CLI](https://github.com/origincloudhq/cli) with the account's own
credentials instead, which serves the same tools on its machine.

### The server's credential for the STS

The server proves itself to the STS with the workload certificate its pod holds
from the zone's certificate authority. A directory (`--workload-dir`) holds
what the enrolment client keeps: `workload.key` (PKCS#8 PEM), `workload.crt`,
`chain.crt` (the intermediate) and `root.crt`. For each exchange the server
signs a one-minute assertion with that key (ES256; the certificate, the
intermediate and the root in `x5c`; the workload's SPIFFE id, `--workload-id`,
as issuer and subject; the STS of `--sts-zone` as audience; issued five
seconds before it is made, so that a clock a little behind doesn't refuse it). The STS takes only
the one workload it is configured with, and only while the authority lists its
certificate as live. The files are read for every assertion, so a renewed
certificate is used at once, and the key never leaves the process. Without the
files the server can't exchange: tool calls fail, and a token that needs the
STS is answered `503`.

The server keeps no MCP sessions: each request is answered on its own, so
that any replica can answer any request. Each caller's SDK client is kept
across requests, so that a read shows the caller's earlier writes.

## Running it

```sh
cargo run -- --sts-url https://sts.example.com --sts-zone zone-1 \
  --workload-dir /path/to/workload --workload-id spiffe://example.com/mcp-server
```

Every flag can be set by an environment variable instead; `--help` lists
them. The defaults are Origin Cloud's production values.

| Flag | Variable | Default | What it is |
|---|---|---|---|
| `--listen` | `MCP_LISTEN_ADDRESS` | `0.0.0.0:8080` | The MCP endpoint and the metadata |
| `--metrics-listen` | `MCP_METRICS_LISTEN_ADDRESS` | `0.0.0.0:9090` | `/metrics`, `/healthz`, `/readyz` |
| `--resource` | `MCP_RESOURCE` | `https://mcp.origincloudapis.eu` | The canonical URI; the MCP endpoint is its path |
| `--audience` | `MCP_AUDIENCE` | the canonical URI | The audience a token must carry |
| `--issuer` | `MCP_ISSUER` | `https://auth.origincloud.eu/realms/origincloud` | The realm people sign in at, the authorization server clients log in to |
| `--scopes` | `MCP_SCOPES` | `mcp` | The scopes a client requests, space-separated |
| `--allowed-clients` | `MCP_ALLOWED_CLIENTS` | none | Restricts the server to tokens issued to these clients, comma-separated; any client's token otherwise |
| `--sts-url` | `MCP_STS_URL` | none, required | The base URL of the STS that exchanges tokens, as its zone's workloads reach it; `https`. Its host must be the STS's internal name: the STS decides by the request's `Host` whether it takes an actor's exchange, and refuses it on its public name |
| `--sts-zone` | `MCP_STS_ZONE` | none, required | The zone of that STS |
| `--sts-ca-file` | `MCP_STS_CA_FILE` | none | PEM certificates that are the only trust for the STS's name |
| `--workload-dir` | `MCP_WORKLOAD_DIR` | none, required | The directory of the server's workload certificate |
| `--workload-id` | `MCP_WORKLOAD_ID` | none, required | The workload's SPIFFE id |
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
  route, status, duration, `x-request-id`, the token's subject and client,
  and the service account the connection acts as, if any. Tokens are never
  logged.
- **Metrics** (Prometheus, on the metrics port):
  `origincloud_http_requests_total`, `origincloud_http_request_duration_seconds`,
  `origincloud_http_requests_in_flight`, `origincloud_mcp_tool_calls_total{tool,outcome}`,
  `origincloud_mcp_token_exchanges_total{outcome}`,
  `origincloud_mcp_auth_refusals_total{reason}` (`missing`, `invalid`, `client`,
  `impersonation`, `unavailable`) and `origincloud_build_info`.
- **Health:** `/healthz` answers while the process runs; `/readyz` once the
  realm's configuration has been read, and until a termination signal.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md), and [RELEASING.md](RELEASING.md) for
how a release is made.

## License

Apache License 2.0; see [LICENSE](LICENSE).
