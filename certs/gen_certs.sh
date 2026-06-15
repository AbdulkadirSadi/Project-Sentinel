#!/bin/bash
set -e
DIR="$(dirname "$(realpath "$0")")"
cd "$DIR"

echo "[1/5] Generating CA key and certificate..."
openssl genrsa -out ca.key 4096
openssl req -new -x509 -days 3650 -key ca.key -out ca.crt \
  -subj "/C=TR/O=Sentinel XDR/CN=Sentinel-CA"

echo "[2/5] Generating server key and certificate..."
openssl genrsa -out server.key 2048
openssl req -new -key server.key -out server.csr \
  -subj "/C=TR/O=Sentinel XDR/CN=sentinel-server"
openssl x509 -req -days 3650 -in server.csr \
  -CA ca.crt -CAkey ca.key -CAcreateserial \
  -out server.crt

echo "[3/5] Generating agent client key and certificate (mTLS)..."
openssl genrsa -out agent-client.key 2048
openssl req -new -key agent-client.key -out agent-client.csr \
  -subj "/C=TR/O=Sentinel XDR/CN=sentinel-agent"
openssl x509 -req -days 3650 -in agent-client.csr \
  -CA ca.crt -CAkey ca.key -CAcreateserial \
  -out agent-client.crt

echo "[4/5] Setting secure permissions..."
chmod 600 ca.key server.key agent-client.key
chmod 644 ca.crt server.crt agent-client.crt

echo "[5/5] Verifying certificates..."
openssl verify -CAfile ca.crt server.crt
openssl verify -CAfile ca.crt agent-client.crt

echo ""
echo "=== Certificates generated in: $DIR ==="
ls -la "$DIR"
