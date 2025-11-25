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

# RSA key size (can override via KEY_SIZE=4096 ./make-ca-and-certs.sh)
KEY_SIZE=${KEY_SIZE:-2048}

# Output directories
CLIENT_CERT_DIR=${CLIENT_CERT_DIR:-"client_certs"}
mkdir -p "$CLIENT_CERT_DIR"
SERVER_CERT_DIR=${SERVER_CERT_DIR:-"server_certs"}
mkdir -p "$SERVER_CERT_DIR"

# Filenames
CA_KEY="$CLIENT_CERT_DIR/${CA_NAME}_key.pem"
CA_CERT="$CLIENT_CERT_DIR/${CA_NAME}_cert.pem"

SERVER_KEY="$SERVER_CERT_DIR/${SERVER_NAME}_key.pem"
SERVER_CSR="$SERVER_CERT_DIR/${SERVER_NAME}_csr.pem"
SERVER_CERT="$SERVER_CERT_DIR/${SERVER_NAME}_cert.pem"

CLIENT_KEY="$CLIENT_CERT_DIR/${CLIENT_NAME}_key.pem"
CLIENT_CSR="$CLIENT_CERT_DIR/${CLIENT_NAME}_csr.pem"
CLIENT_CERT="$CLIENT_CERT_DIR/${CLIENT_NAME}_cert.pem"

# Generate CA
echo "[1/5] Generating CA key and certificate..."
openssl genrsa -out "$CA_KEY" ${KEY_SIZE}
CA_SUBJ="/C=US/ST=State/L=City/O=ExampleOrg/OU=Dev/CN=${CA_NAME}"
openssl req -x509 -new -nodes -key "$CA_KEY" -sha256 -days "$CA_DAYS" \
  -subj "$CA_SUBJ" -out "$CA_CERT"

# Generate Server CSR and Certificate
echo "[2/5] Generating server key and CSR..."
openssl genrsa -out "$SERVER_KEY" ${KEY_SIZE}

SERVER_SAN_CONFIG=$(cat <<EOF
[ req ]
default_bits       = ${KEY_SIZE}
prompt             = no
distinguished_name = dn
req_extensions     = req_ext

[ dn ]
CN = ${SERVER_NAME}

[ req_ext ]
subjectAltName = @alt_names

[ alt_names ]
DNS.1 = ${SERVER_NAME}
DNS.2 = localhost
IP.1  = 127.0.0.1

[ v3_ext ]
extendedKeyUsage = serverAuth
subjectAltName = @alt_names
EOF
)

openssl req -new -key "$SERVER_KEY" -out "$SERVER_CSR" \
  -config <(printf "%s\n" "$SERVER_SAN_CONFIG")

echo "[3/5] Signing server certificate with CA..."
openssl x509 -req -in "$SERVER_CSR" -CA "$CA_CERT" -CAkey "$CA_KEY" -CAcreateserial \
  -out "$SERVER_CERT" -days "$SERVER_DAYS" -sha256 \
  -extfile <(printf "%s\n" "$SERVER_SAN_CONFIG") -extensions v3_ext

# Generate Client CSR and Certificate
echo "[4/5] Generating client key and CSR..."
openssl genrsa -out "$CLIENT_KEY" ${KEY_SIZE}

CLIENT_SUBJ="/C=AA/L=City/O=ExampleOrg/OU=Dev/CN=${CLIENT_NAME}"
CLIENT_REQ_CONFIG=$(cat <<EOF
[ req ]
default_bits       = ${KEY_SIZE}
prompt             = no
distinguished_name = dn
req_extensions     = req_ext

[ dn ]
CN = ${CLIENT_NAME}

[ req_ext ]
extendedKeyUsage = clientAuth

[ v3_ext ]
extendedKeyUsage = clientAuth
EOF
)

openssl req -new -key "$CLIENT_KEY" -out "$CLIENT_CSR" -subj "$CLIENT_SUBJ" \
  -config <(printf "%s\n" "$CLIENT_REQ_CONFIG")

echo "[5/5] Signing client certificate with CA..."
openssl x509 -req -in "$CLIENT_CSR" -CA "$CA_CERT" -CAkey "$CA_KEY" -CAcreateserial \
  -out "$CLIENT_CERT" -days "$CLIENT_DAYS" -sha256 \
  -extfile <(printf "%s\n" "$CLIENT_REQ_CONFIG") -extensions v3_ext

chmod 600 "$CA_KEY" "$SERVER_KEY" "$CLIENT_KEY"
chmod 600 "$CA_CERT" "$SERVER_CERT" "$CLIENT_CERT"

cp "$CA_CERT" "$SERVER_CERT_DIR"

echo "Certificates and keys generated"
