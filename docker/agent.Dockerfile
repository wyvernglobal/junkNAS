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
    apt-get install -y --no-install-recommends ca-certificates wireguard-tools boringtun && \
    rm -rf /var/lib/apt/lists/*

RUN useradd -m junknas
USER junknas

WORKDIR /home/junknas
COPY --from=build /app/target/release/junknas-agent /usr/local/bin/junknas-agent

ENV JUNKNAS_CONTROLLER_URL="http://10.44.0.1:8080/api"

ENTRYPOINT ["/usr/local/bin/junknas-agent"]
