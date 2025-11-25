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

# Minimal runtime deps
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /root
COPY --from=build /app/target/release/junknas-controller /usr/local/bin/junknas-controller

EXPOSE 8080
ENTRYPOINT ["/usr/local/bin/junknas-controller"]
