#!/usr/bin/env bash
set -euo pipefail

$OUT_DIR="$(cd "$(dirname "$0")" && pwd)"

mkdir -p "$OUT_DIR"

# Optional cleanup
rm -f "$OUT_DIR"/ec-key{1..3}.pem "$OUT_DIR"/ec-pubCert{1..3}.pem

gen() {
  i="$1"
  openssl ecparam -name prime256v1 -genkey -noout -out "$OUT_DIR/ec-key${i}.pem"
  # OpenSSL 3.x supports -addext. If your openssl lacks -addext, use the config method below.
  openssl req -new -x509 -key "$OUT_DIR/ec-key${i}.pem" -out "$OUT_DIR/ec-pubCert${i}.pem" -days 3650 \
    -subj "/C=US/ST=Test/L=Test/O=Test/OU=Dev/CN=webkms-ec-${i}" \
    -addext "basicConstraints=CA:TRUE" \
    -addext "keyUsage=critical,digitalSignature,keyEncipherment" \
    -addext "extendedKeyUsage=serverAuth,clientAuth" \
    -addext "subjectAltName=DNS:localhost,IP:127.0.0.1"
}

for i in 1 2 3; do
  gen "$i"
done

echo "Regenerated EC certs with SAN: localhost and 127.0.0.1"
