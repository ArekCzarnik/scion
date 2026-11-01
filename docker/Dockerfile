# syntax=docker/dockerfile:1
# Images for docker/compose.yml; build context is the repository root.
#   docker compose -f docker/compose.yml build            # target: server
#   docker build -f docker/Dockerfile --target cli -t scion-cli:local .
#
# rust-toolchain.toml is not copied: it would make rustup fetch rustfmt and clippy, and the image
# tag below already pins the same Rust version.

FROM rust:1.98.0-bookworm AS builder
RUN apt-get update \
    && apt-get install -y --no-install-recommends protobuf-compiler \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /src
COPY Cargo.toml Cargo.lock ./
COPY .cargo .cargo
COPY crates crates
COPY proto proto
RUN --mount=type=cache,id=scion-cargo-registry,target=/usr/local/cargo/registry \
    --mount=type=cache,id=scion-cargo-target,target=/src/target \
    cargo build --release --locked -p scion-server -p scion-cli -p scion-import \
    && install -D -t /out target/release/scion-server target/release/scion target/release/scion-import

FROM debian:bookworm-slim AS server
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates curl openssl \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --system --uid 10001 --user-group --no-create-home scion \
    && install -d -o scion -g scion /var/lib/scion/secrets /var/lib/scion/client \
        /var/lib/scion/admin
COPY --from=builder /out/scion-server /usr/local/bin/
COPY docker/server-entrypoint.sh /usr/local/bin/
USER scion
EXPOSE 7443
ENTRYPOINT ["server-entrypoint.sh"]
CMD ["scion-server", "/etc/scion/scion-server.toml"]

FROM debian:bookworm-slim AS cli
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/*
COPY --from=builder /out/scion /out/scion-import /usr/local/bin/
COPY docker/cli-entrypoint.sh /usr/local/bin/
# Defaults for a client that shares the compose network and the scion-client volume. HOME is
# throwaway because the entrypoint logs in on every run and any --user may be in effect.
ENV SCION_ENDPOINT=https://scion-server:7443 \
    SCION_CA_FILE=/var/lib/scion/client/ca.crt \
    SCION_SERVICE_NAME=agent \
    SCION_SERVICE_SECRET_FILE=/var/lib/scion/client/agent.secret \
    HOME=/tmp
USER 10001
ENTRYPOINT ["cli-entrypoint.sh"]
