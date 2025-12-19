# syntax=docker/dockerfile:1

# Build

FROM rust:1.91-bookworm AS builder
WORKDIR /build

# Install dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    pkg-config \
    libtss2-dev \
    clang \
    && rm -rf /var/lib/apt/lists/*

# Optimise release binary
ENV CARGO_PROFILE_RELEASE_LTO=true \
    CARGO_PROFILE_RELEASE_CODEGEN_UNITS=1

# Cache dependencies
COPY Cargo.toml Cargo.lock ./

COPY dummy-attestation-server/Cargo.toml dummy-attestation-server/Cargo.toml
RUN mkdir -p dummy-attestation-server/src && echo "fn main(){}" > dummy-attestation-server/src/main.rs

RUN mkdir -p src && echo "fn main(){}" > src/main.rs
RUN cargo build --release
RUN rm -rf src
RUN rm -rf dummy-attestation-server/src

# Build real binary
COPY . .
RUN cargo build -p attested-tls-proxy --release

# Run

FROM debian:bookworm-slim

# Install dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    libtss2-dev \
    && rm -rf /var/lib/apt/lists/*

RUN useradd -u 10001 -m appuser
USER 10001:10001
WORKDIR /app

# TODO this should specify allowed attestation types, so as not to allow 'none'
RUN echo "[{}]" > /app/measurements-empty.json

COPY --from=builder /build/target/release/attested-tls-proxy /app/attested-tls-proxy

EXPOSE 8443

# TODO do we need to also expose a port for heath checks

# No shell in distroless; use exec form
ENTRYPOINT ["/app/attested-tls-proxy"]
