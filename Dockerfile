# Build stage
FROM rust:1.88.0-slim-bookworm AS builder

# Space-delimited Cargo feature list. `auto` enables Azure support on amd64 and
# disables it on other architectures.
ARG FEATURES=auto

RUN apt-get update && apt-get install -y \
    pkg-config clang libclang-dev \
    openssl libssl-dev libtss2-dev \
    perl make \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY . .

# Resolve the architecture-dependent default, then build with exactly the
# requested features. An explicitly empty FEATURES value enables no features.
RUN build_features="$FEATURES"; \
    if [ "$build_features" = "auto" ]; then \
        if [ "$(dpkg --print-architecture)" = "amd64" ]; then \
            build_features="azure"; \
        else \
            build_features=""; \
            echo "WARNING: Building on ARM without Azure/TPM features (cross-compilation not supported)"; \
        fi; \
    fi; \
    if [ -n "$build_features" ]; then \
        cargo build --release --no-default-features --features "$build_features"; \
    else \
        cargo build --release --no-default-features; \
    fi

# Runtime stage
FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y \
    ca-certificates libssl3 libtss2-dev \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /app/target/release/attested-tls-proxy /usr/local/bin/

ENTRYPOINT ["/usr/local/bin/attested-tls-proxy"]
