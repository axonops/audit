#!/usr/bin/env bash
#
# generate-test-certs.sh — Generate test certificates for TLS and mTLS testing.
#
# Generates:
#   1. Self-signed CA (10-year expiry)
#   2. Server certificate signed by CA (localhost, 127.0.0.1, ::1)
#   3. Client certificate signed by CA (for mTLS)
#   4. Invalid certificate (self-signed, NOT signed by CA)
#
# Key type: ECDSA P-256 (fast, modern standard).
# Output:   tests/testdata/certs/
#
# This script is idempotent — re-running overwrites existing files.
# Generated certificates are committed to the repo as test fixtures.

set -euo pipefail

CERT_DIR="$(cd "$(dirname "$0")/.." && pwd)/tests/testdata/certs"
DAYS=3650  # ~10 years

mkdir -p "$CERT_DIR"

echo "=== Generating test certificates in $CERT_DIR ==="

# --- 1. Test CA ---
echo "--- CA certificate ---"
openssl ecparam -genkey -name prime256v1 -noout -out "$CERT_DIR/ca.key" 2>/dev/null

cat > "$CERT_DIR/ca.cnf" <<EOF
[req]
distinguished_name = req_dn
x509_extensions = v3_ca
prompt = no

[req_dn]
CN = go-audit Test CA
O = AxonOps
OU = Testing

[v3_ca]
basicConstraints = critical, CA:TRUE
keyUsage = critical, keyCertSign, cRLSign
subjectKeyIdentifier = hash
EOF

openssl req -new -x509 -key "$CERT_DIR/ca.key" \
  -out "$CERT_DIR/ca.crt" \
  -days "$DAYS" \
  -config "$CERT_DIR/ca.cnf" \
  -sha256 2>/dev/null

# --- 2. Server certificate (signed by CA) ---
echo "--- Server certificate ---"
openssl ecparam -genkey -name prime256v1 -noout -out "$CERT_DIR/server.key" 2>/dev/null

# Create a config with SANs for localhost, 127.0.0.1, ::1
cat > "$CERT_DIR/server.cnf" <<EOF
[req]
distinguished_name = req_dn
req_extensions = v3_req
prompt = no

[req_dn]
CN = localhost

[v3_req]
subjectAltName = DNS:localhost,IP:127.0.0.1,IP:::1
keyUsage = digitalSignature
extendedKeyUsage = serverAuth
EOF

openssl req -new -key "$CERT_DIR/server.key" \
  -out "$CERT_DIR/server.csr" \
  -config "$CERT_DIR/server.cnf" 2>/dev/null

openssl x509 -req -in "$CERT_DIR/server.csr" \
  -CA "$CERT_DIR/ca.crt" -CAkey "$CERT_DIR/ca.key" \
  -CAcreateserial \
  -out "$CERT_DIR/server.crt" \
  -days "$DAYS" \
  -sha256 \
  -extfile "$CERT_DIR/server.cnf" -extensions v3_req 2>/dev/null

# --- 3. Client certificate (signed by CA, for mTLS) ---
echo "--- Client certificate ---"
openssl ecparam -genkey -name prime256v1 -noout -out "$CERT_DIR/client.key" 2>/dev/null
openssl req -new -key "$CERT_DIR/client.key" \
  -out "$CERT_DIR/client.csr" \
  -subj "/CN=test-client/O=AxonOps/OU=Testing" 2>/dev/null

cat > "$CERT_DIR/client.cnf" <<EOF
[v3_client]
keyUsage = digitalSignature
extendedKeyUsage = clientAuth
EOF

openssl x509 -req -in "$CERT_DIR/client.csr" \
  -CA "$CERT_DIR/ca.crt" -CAkey "$CERT_DIR/ca.key" \
  -CAcreateserial \
  -out "$CERT_DIR/client.crt" \
  -days "$DAYS" \
  -sha256 \
  -extfile "$CERT_DIR/client.cnf" -extensions v3_client 2>/dev/null

# --- 4. Invalid certificate (self-signed, NOT signed by CA) ---
echo "--- Invalid certificate (self-signed) ---"
openssl ecparam -genkey -name prime256v1 -noout -out "$CERT_DIR/invalid.key" 2>/dev/null
openssl req -new -x509 -key "$CERT_DIR/invalid.key" \
  -out "$CERT_DIR/invalid.crt" \
  -days "$DAYS" \
  -subj "/CN=invalid-cert/O=Untrusted/OU=Testing" \
  -sha256 2>/dev/null

# --- Cleanup intermediate files and tighten key permissions ---
rm -f "$CERT_DIR"/*.csr "$CERT_DIR"/*.cnf "$CERT_DIR"/*.srl
chmod 600 "$CERT_DIR"/*.key

echo "=== Done. Generated files: ==="
ls -la "$CERT_DIR"/*.crt "$CERT_DIR"/*.key
echo ""
echo "CA:      $CERT_DIR/ca.crt, ca.key"
echo "Server:  $CERT_DIR/server.crt, server.key (SANs: localhost, 127.0.0.1, ::1)"
echo "Client:  $CERT_DIR/client.crt, client.key (CN=test-client)"
echo "Invalid: $CERT_DIR/invalid.crt, invalid.key (self-signed, NOT from CA)"
