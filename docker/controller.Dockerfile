# Multi-stage: build then run as non-root
FROM rust:1.85-slim-bookworm AS build

WORKDIR /app
COPY Cargo.toml /app/Cargo.toml
COPY controller/Cargo.toml /app/controller/Cargo.toml
COPY agent/Cargo.toml /app/agent/Cargo.toml
COPY controller/src /app/controller/src
COPY agent/src /app/agent/src

RUN cargo build -p junknas-controller --release

FROM debian:bookworm-slim

# Minimal runtime deps + WireGuard tooling so the controller can host the mesh
# and Samba so the controller can export the cluster filesystem directly.
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    wireguard \
    wireguard-tools \
    iproute2 \
    samba \
    samba-common-bin \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /root
COPY --from=build /app/target/release/junknas-controller /usr/local/bin/junknas-controller
COPY dashboard/static/ /srv/junknas-dashboard/
COPY docker/controller-entrypoint.sh /usr/local/bin/controller-entrypoint.sh

EXPOSE 8008
EXPOSE 8080
EXPOSE 445
EXPOSE 51820/udp
ENTRYPOINT ["/usr/local/bin/controller-entrypoint.sh"]
