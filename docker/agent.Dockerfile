FROM rust:1.85-slim-bookworm AS build

WORKDIR /app
COPY Cargo.toml /app/Cargo.toml
COPY controller/Cargo.toml /app/controller/Cargo.toml
COPY agent/Cargo.toml /app/agent/Cargo.toml
COPY controller/src /app/controller/src
COPY agent/src /app/agent/src

RUN cargo build -p junknas-agent --release

FROM debian:bookworm-slim

RUN apt-get update && \
    apt-get install -y --no-install-recommends ca-certificates wireguard wireguard-tools iproute2 && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /root
COPY --from=build /app/target/release/junknas-agent /usr/local/bin/junknas-agent

ENV JUNKNAS_CONTROLLER_URL="http://10.44.0.1:8008/api"
ENV JUNKNAS_WG_ENDPOINT_PORT="58008"
ENV JUNKNAS_WG_ALLOWED_IPS="fd44::/64"
ENV JUNKNAS_WG_DNS="fd44::1"

ENTRYPOINT ["/usr/local/bin/junknas-agent"]
