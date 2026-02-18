# Build stage
FROM rust:1.88.0-slim-bookworm AS builder

# Build arguments for feature control
# On x86_64: use "default" for full features including Azure/TPM
# On ARM (cross-compile not supported for TPM): features will be ignored, uses --no-default-features
ARG FEATURES=default

RUN apt-get update && apt-get install -y \
    pkg-config clang libclang-dev \
    openssl libssl-dev libtss2-dev \
    perl make \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY . .

# On x86_64: build with requested features
# On ARM: build without azure/TPM features (cross-compilation not supported for TPM libs)
RUN if [ "$(dpkg --print-architecture)" = "amd64" ]; then \
        cargo build --release --features azure "$FEATURES"; \
    else \
        echo "WARNING: Building on ARM without Azure/TPM features (cross-compilation not supported)" && \
        cargo build --release; \
    fi

# Runtime stage
FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y \
    ca-certificates libssl3 libtss2-dev \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /app/target/release/attested-tls-proxy /usr/local/bin/

ENTRYPOINT ["/usr/local/bin/attested-tls-proxy"]

