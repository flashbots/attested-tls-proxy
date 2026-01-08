#!/usr/bin/env bash

# Checks reproducibility by running a package build twice and printing hashes of .deb package

set -euo pipefail

rm -rf /tmp/repro1 /tmp/repro2
mkdir -p /tmp/repro1 /tmp/repro2

docker build -f Dockerfile.build-deb --no-cache --output type=local,dest=/tmp/repro1 .
docker build -f Dockerfile.build-deb --no-cache --output type=local,dest=/tmp/repro2 .

sha256sum /tmp/repro1/debian/*.deb
sha256sum /tmp/repro2/debian/*.deb
