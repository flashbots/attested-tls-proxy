# Build stage
FROM rust:1.88.0-slim-bookworm AS builder

# Optional space-delimited Cargo feature list.
ARG FEATURES=""

RUN apt-get update && apt-get install -y \
    pkg-config clang libclang-dev \
    openssl libssl-dev \
    perl make \
    && rm -rf /var/lib/apt/lists/*

RUN cargo install cargo-auditable@0.7.7 --locked

WORKDIR /app
COPY . .

RUN if [ -n "$FEATURES" ]; then \
        cargo auditable build -p attested-tls-proxy --locked --release --no-default-features --features "$FEATURES"; \
    else \
        cargo auditable build -p attested-tls-proxy --locked --release --no-default-features; \
    fi

# Runtime stage
FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y \
    ca-certificates libssl3 \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /app/target/release/attested-tls-proxy /usr/local/bin/

ENTRYPOINT ["/usr/local/bin/attested-tls-proxy"]
