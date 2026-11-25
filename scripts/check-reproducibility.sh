#!/usr/bin/env bash

# Build release artifacts twice and require matching hashes. Pass
# provider-artifacts to check only the standalone provider binary.

set -euo pipefail

build_stage=${1:-artifacts}
repro_dir=$(mktemp -d)
trap 'rm -rf "$repro_dir"' EXIT

rust_toolchain=${RUST_TOOLCHAIN:-$(rustc --version | cut -d' ' -f2)}
rust_image=${RUST_IMAGE:-$(docker buildx imagetools inspect "docker.io/rust:$rust_toolchain-trixie" --format '{{.Name}}@{{.Manifest.Digest}}')}
features=${FEATURES-azure}
source_date=${SOURCE_DATE:-$(git log -1 --pretty=%ct)}

for build in 1 2; do
    # Reuse the identical native toolchain while forcing fresh Cargo builds.
    docker build -f Dockerfile.build-deb \
        --no-cache-filter proxy-builder --no-cache-filter provider-builder \
        --no-cache-filter package-builder \
        --target "$build_stage" \
        --build-arg "RUST_TOOLCHAIN=$rust_toolchain" \
        --build-arg "RUST_IMAGE=$rust_image" \
        --build-arg "FEATURES=$features" \
        --build-arg "VERSION=${VERSION:-}" \
        --build-arg "SOURCE_DATE=$source_date" \
        --output "type=local,dest=$repro_dir/$build" .

    (
        cd "$repro_dir/$build"
        sha256sum reproducible/attestation-provider-server
        if [ "$build_stage" = artifacts ]; then
            sha256sum reproducible/attested-tls-proxy debian/attested-tls-proxy_*.deb
        fi
    ) > "$repro_dir/$build.sha256"
done

cat "$repro_dir/1.sha256"
diff -u "$repro_dir/1.sha256" "$repro_dir/2.sha256"
