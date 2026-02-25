#!/usr/bin/env bash
set -euo pipefail

# Configurable parameters (can override via env vars)
CA_NAME=${CA_NAME:-"local_ca"}
SERVER_NAME=${SERVER_NAME:-"server"}
CLIENT_NAME=${CLIENT_NAME:-"client"}

# Certificate validity periods (days)
CA_DAYS=${CA_DAYS:-3650}        # ~10 years
SERVER_DAYS=${SERVER_DAYS:-825} # ~2+ years
CLIENT_DAYS=${CLIENT_DAYS:-825}

# RSA key size
KEY_SIZE=${KEY_SIZE:-2048}

# Output directories
CA_DIR=${CA_DIR:-"ca"}
CLIENT_CERT_DIR=${CLIENT_CERT_DIR:-"client_certs"}
SERVER_CERT_DIR=${SERVER_CERT_DIR:-"server_certs"}

# Filenames
CA_KEY="$CA_DIR/${CA_NAME}_key.pem"
CA_CERT="$CA_DIR/${CA_NAME}_cert.pem"
CA_SERIAL="$CA_DIR/${CA_NAME}.srl"

SERVER_KEY="$SERVER_CERT_DIR/${SERVER_NAME}_key.pem"
SERVER_CSR="$SERVER_CERT_DIR/${SERVER_NAME}_csr.pem"
SERVER_CERT="$SERVER_CERT_DIR/${SERVER_NAME}_cert.pem"

CLIENT_KEY="$CLIENT_CERT_DIR/${CLIENT_NAME}_key.pem"
CLIENT_CSR="$CLIENT_CERT_DIR/${CLIENT_NAME}_csr.pem"
CLIENT_CERT="$CLIENT_CERT_DIR/${CLIENT_NAME}_cert.pem"

# Guard against accidental overwrite
if [[ -f "$CA_CERT" ]]; then
  echo "CA already exists at '$CA_CERT'. Delete output dirs to regenerate." >&2
  exit 1
fi

mkdir -p "$CA_DIR" "$CLIENT_CERT_DIR" "$SERVER_CERT_DIR"

# --- CA ---
echo "[1/5] Generating CA key and certificate..."
openssl genrsa -out "$CA_KEY" "${KEY_SIZE}"

CA_CONFIG=$(cat <<EOF
[ req ]
default_bits       = ${KEY_SIZE}
prompt             = no
distinguished_name = dn
x509_extensions    = v3_ca

[ dn ]
C  = US
ST = State
L  = City
O  = ExampleOrg
OU = Dev
CN = ${CA_NAME}

[ v3_ca ]
subjectKeyIdentifier   = hash
authorityKeyIdentifier = keyid:always,issuer
basicConstraints       = critical, CA:TRUE
keyUsage               = critical, keyCertSign, cRLSign
EOF
)

openssl req -x509 -new -nodes -key "$CA_KEY" -sha256 -days "$CA_DAYS" \
  -config <(printf "%s\n" "$CA_CONFIG") -out "$CA_CERT"

# --- Server ---
echo "[2/5] Generating server key and CSR..."
openssl genrsa -out "$SERVER_KEY" "${KEY_SIZE}"

SERVER_CONFIG=$(cat <<EOF
[ req ]
prompt             = no
distinguished_name = dn

[ dn ]
CN = ${SERVER_NAME}

[ v3_ext ]
subjectKeyIdentifier   = hash
authorityKeyIdentifier = keyid,issuer
basicConstraints       = critical, CA:FALSE
keyUsage               = critical, digitalSignature, keyEncipherment
extendedKeyUsage       = serverAuth
subjectAltName         = @alt_names

[ alt_names ]
DNS.1 = ${SERVER_NAME}
DNS.2 = localhost
IP.1  = 127.0.0.1
EOF
)

openssl req -new -key "$SERVER_KEY" -out "$SERVER_CSR" \
  -config <(printf "%s\n" "$SERVER_CONFIG")

echo "[3/5] Signing server certificate with CA..."
openssl x509 -req -in "$SERVER_CSR" -CA "$CA_CERT" -CAkey "$CA_KEY" \
  -CAserial "$CA_SERIAL" -CAcreateserial \
  -out "$SERVER_CERT" -days "$SERVER_DAYS" -sha256 \
  -extfile <(printf "%s\n" "$SERVER_CONFIG") -extensions v3_ext

# --- Client ---
echo "[4/5] Generating client key and CSR..."
openssl genrsa -out "$CLIENT_KEY" "${KEY_SIZE}"

CLIENT_CONFIG=$(cat <<EOF
[ req ]
prompt             = no
distinguished_name = dn

[ dn ]
C  = AA
L  = City
O  = ExampleOrg
OU = Dev
CN = ${CLIENT_NAME}

[ v3_ext ]
subjectKeyIdentifier   = hash
authorityKeyIdentifier = keyid,issuer
basicConstraints       = critical, CA:FALSE
keyUsage               = critical, digitalSignature
extendedKeyUsage       = clientAuth
EOF
)

openssl req -new -key "$CLIENT_KEY" -out "$CLIENT_CSR" \
  -config <(printf "%s\n" "$CLIENT_CONFIG")

echo "[5/5] Signing client certificate with CA..."
openssl x509 -req -in "$CLIENT_CSR" -CA "$CA_CERT" -CAkey "$CA_KEY" \
  -CAserial "$CA_SERIAL" \
  -out "$CLIENT_CERT" -days "$CLIENT_DAYS" -sha256 \
  -extfile <(printf "%s\n" "$CLIENT_CONFIG") -extensions v3_ext

# Permissions: private keys 600, certs 644
chmod 600 "$CA_KEY" "$SERVER_KEY" "$CLIENT_KEY"
chmod 644 "$CA_CERT" "$SERVER_CERT" "$CLIENT_CERT"

# Copy CA cert to server dir so it can verify client certs, and vice versa
cp "$CA_CERT" "$SERVER_CERT_DIR/"
cp "$CA_CERT" "$CLIENT_CERT_DIR/"

# Remove intermediate CSR files
rm -f "$SERVER_CSR" "$CLIENT_CSR"

echo ""
echo "Done. Files generated:"
echo "  CA:     $CA_KEY  $CA_CERT"
echo "  Server: $SERVER_KEY  $SERVER_CERT"
echo "  Client: $CLIENT_KEY  $CLIENT_CERT"
