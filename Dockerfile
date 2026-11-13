# syntax=docker/dockerfile:1

# The server in a distroless image, run as a user without privileges.
FROM rust:1.97.1-slim-trixie AS build
WORKDIR /src
COPY . .
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/usr/local/cargo/git \
    --mount=type=cache,target=/src/target \
    cargo build --release --locked \
    && cp target/release/origincloud-mcp-server /origincloud-mcp-server

FROM gcr.io/distroless/cc-debian13:nonroot
COPY --from=build /origincloud-mcp-server /origincloud-mcp-server
# Numeric, so that a pod with runAsNonRoot can verify it (Kubernetes can't
# check a user given by name): distroless's nonroot is 65532.
USER 65532:65532
# 8080: the MCP endpoint and the protected resource metadata. 9090:
# /metrics, /healthz and /readyz.
EXPOSE 8080 9090
ENTRYPOINT ["/origincloud-mcp-server"]
