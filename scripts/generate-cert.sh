#!/usr/bin/env bash

# Script to generate a certificate chain with a mock CA for testing
#
# Requires `openssl` to be installed
#
# Usage: ./generate-cert.sh HOSTNAME IPADDR
#
# On GCP the hostname is the IP address in reverse order followed by `@googleusercontent.com`
# For example:
# ./generate-cert.sh 227.107.63.34@googleusercontent.com 34.63.107.227
#
# The ca.crt file then needs to be transfered to the client, and given with
# `--tls-ca-certificate ca.crt` when starting proxy-client

set -euo pipefail

# -------- config --------
HOSTNAME="${1:-localhost}"
IPADDR="${2:-127.0.0.1}"

echo "==> Generating certificates for:"
echo "    DNS: $HOSTNAME"
echo "    IP : $IPADDR"
echo ""

# Clean old files
rm -f ca.key ca.crt ca.srl server.key server.csr server.crt

# -------- CA key + cert --------
echo "==> Creating CA private key"
openssl genrsa -out ca.key 4096

echo "==> Creating CA certificate"
openssl req -x509 -new -key ca.key -sha256 -days 3650 \
	  -subj "/CN=My Test CA" \
	    -addext "basicConstraints=critical,CA:true,pathlen:0" \
	      -addext "keyUsage=critical,keyCertSign,cRLSign" \
	        -out ca.crt

# -------- Server key + CSR --------
echo "==> Creating server private key"
openssl genrsa -out server.key 2048

echo "==> Creating server CSR"
openssl req -new -key server.key \
	  -subj "/CN=${HOSTNAME}" \
	    -out server.csr

# -------- Server certificate signed by CA --------
echo "==> Creating server certificate signed by CA"

# Build SAN extension file dynamically
EXTFILE=$(mktemp)
cat > "$EXTFILE" <<EOF
basicConstraints=CA:false
keyUsage=digitalSignature,keyEncipherment
extendedKeyUsage=serverAuth
subjectAltName=DNS:${HOSTNAME},IP:${IPADDR}
EOF

openssl x509 -req -in server.csr \
	  -CA ca.crt -CAkey ca.key -CAcreateserial \
	    -out server.crt -days 365 -sha256 \
	      -extfile "$EXTFILE"

rm -f "$EXTFILE"

echo ""
echo "==> Done"
echo "Generated files:"
echo "  ca.key        # CA private key"
echo "  ca.crt        # CA certificate (required by client)"
echo "  server.key    # Server private key"
echo "  server.crt    # Server certificate signed by CA"
echo ""

