#!/usr/bin/env python3
"""
Generate a local CA, server certificate, and client certificate for mTLS.

Requirements:
    pip install cryptography

Usage:
    python make_ca_and_certs.py
"""

import ipaddress
import argparse
import sys
from datetime import datetime, timezone, timedelta
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

parser = argparse.ArgumentParser(description="Generate a local CA, server, and client certificate for mTLS.")
parser.add_argument("--ca-name",        default="local_ca",        help="CA common name (default: local_ca)")
parser.add_argument("--server-name",    default="server",          help="Server common name (default: server)")
parser.add_argument("--client-name",    default="client",          help="Client common name (default: client)")
parser.add_argument("--ca-days",        type=int, default=3650,    help="CA certificate validity in days (default: 3650)")
parser.add_argument("--server-days",    type=int, default=825,     help="Server certificate validity in days (default: 825)")
parser.add_argument("--client-days",    type=int, default=825,     help="Client certificate validity in days (default: 825)")
parser.add_argument("--key-size",       type=int, default=2048,    help="RSA key size in bits (default: 2048)")
parser.add_argument("--ca-dir",         default="__ca",            help="Output directory for CA files (default: __ca)")
parser.add_argument("--server-dir",     default="__server_certs",  help="Output directory for server cert files (default: __server_certs)")
parser.add_argument("--client-dir",     default="__client_certs",  help="Output directory for client cert files (default: __client_certs)")
args = parser.parse_args()

CA_NAME     = args.ca_name
SERVER_NAME = args.server_name
CLIENT_NAME = args.client_name
CA_DAYS     = args.ca_days
SERVER_DAYS = args.server_days
CLIENT_DAYS = args.client_days
KEY_SIZE    = args.key_size
CA_DIR      = Path(args.ca_dir)
SERVER_DIR  = Path(args.server_dir)
CLIENT_DIR  = Path(args.client_dir)

ca_cert_path = CA_DIR / f"{CA_NAME}_cert.pem"
if ca_cert_path.exists():
    print(f"CA already exists at '{ca_cert_path}'. Delete output dirs to regenerate.", file=sys.stderr)
    sys.exit(1)

for d in (CA_DIR, SERVER_DIR, CLIENT_DIR):
    d.mkdir(parents=True, exist_ok=True)

now = datetime.now(timezone.utc)

def new_key():
    return rsa.generate_private_key(public_exponent=65537, key_size=KEY_SIZE)

def base_builder(subject: x509.Name, issuer: x509.Name, key, days: int):
    return (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + timedelta(days=days))
    )

def save(path: Path, data: bytes, mode: int):
    path.write_bytes(data)
    path.chmod(mode)

# --- CA ---
print("[1/3] Generating CA...")
ca_key = new_key()
ca_name = x509.Name([
    x509.NameAttribute(NameOID.COUNTRY_NAME,             "US"),
    x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME,   "State"),
    x509.NameAttribute(NameOID.LOCALITY_NAME,            "City"),
    x509.NameAttribute(NameOID.ORGANIZATION_NAME,        "ExampleOrg"),
    x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, "Dev"),
    x509.NameAttribute(NameOID.COMMON_NAME,              CA_NAME),
])
ca_cert = (
    base_builder(ca_name, ca_name, ca_key, CA_DAYS)
    .add_extension(x509.SubjectKeyIdentifier.from_public_key(ca_key.public_key()), critical=False)
    .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()), critical=False)
    .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
    .add_extension(x509.KeyUsage(
        digital_signature=False, content_commitment=False, key_encipherment=False,
        data_encipherment=False, key_agreement=False, key_cert_sign=True,
        crl_sign=True, encipher_only=False, decipher_only=False,
    ), critical=True)
    .sign(ca_key, hashes.SHA256())
)
ca_cert_pem = ca_cert.public_bytes(serialization.Encoding.PEM)
save(CA_DIR / f"{CA_NAME}_key.pem",  ca_key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.TraditionalOpenSSL, serialization.NoEncryption()), 0o600)
save(CA_DIR / f"{CA_NAME}_cert.pem", ca_cert_pem, 0o644)

# --- Server ---
print("[2/3] Generating server certificate...")
server_key = new_key()
server_cert = (
    base_builder(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, SERVER_NAME)]), ca_cert.subject, server_key, SERVER_DAYS)
    .add_extension(x509.SubjectKeyIdentifier.from_public_key(server_key.public_key()), critical=False)
    .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()), critical=False)
    .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
    .add_extension(x509.KeyUsage(
        digital_signature=True, content_commitment=False, key_encipherment=True,
        data_encipherment=False, key_agreement=False, key_cert_sign=False,
        crl_sign=False, encipher_only=False, decipher_only=False,
    ), critical=True)
    .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
    .add_extension(x509.SubjectAlternativeName([
        x509.DNSName(SERVER_NAME),
        x509.DNSName("localhost"),
        x509.IPAddress(ipaddress.IPv4Address("127.0.0.1")),
    ]), critical=False)
    .sign(ca_key, hashes.SHA256())
)
save(SERVER_DIR / f"{SERVER_NAME}_key.pem",  server_key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.TraditionalOpenSSL, serialization.NoEncryption()), 0o600)
save(SERVER_DIR / f"{SERVER_NAME}_cert.pem", server_cert.public_bytes(serialization.Encoding.PEM), 0o644)

# --- Client ---
print("[3/3] Generating client certificate...")
client_key = new_key()
client_cert = (
    base_builder(x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME,             "AA"),
        x509.NameAttribute(NameOID.LOCALITY_NAME,            "City"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME,        "ExampleOrg"),
        x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, "Dev"),
        x509.NameAttribute(NameOID.COMMON_NAME,              CLIENT_NAME),
    ]), ca_cert.subject, client_key, CLIENT_DAYS)
    .add_extension(x509.SubjectKeyIdentifier.from_public_key(client_key.public_key()), critical=False)
    .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()), critical=False)
    .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
    .add_extension(x509.KeyUsage(
        digital_signature=True, content_commitment=False, key_encipherment=False,
        data_encipherment=False, key_agreement=False, key_cert_sign=False,
        crl_sign=False, encipher_only=False, decipher_only=False,
    ), critical=True)
    .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH]), critical=False)
    .sign(ca_key, hashes.SHA256())
)
save(CLIENT_DIR / f"{CLIENT_NAME}_key.pem",  client_key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.TraditionalOpenSSL, serialization.NoEncryption()), 0o600)
save(CLIENT_DIR / f"{CLIENT_NAME}_cert.pem", client_cert.public_bytes(serialization.Encoding.PEM), 0o644)

# Copy CA cert to leaf dirs for convenience
save(SERVER_DIR / f"{CA_NAME}_cert.pem", ca_cert_pem, 0o644)
save(CLIENT_DIR / f"{CA_NAME}_cert.pem", ca_cert_pem, 0o644)

print(f"\nDone.")
print(f"  CA:     {CA_DIR}/{CA_NAME}_key.pem,  {CA_DIR}/{CA_NAME}_cert.pem")
print(f"  Server: {SERVER_DIR}/{SERVER_NAME}_key.pem,  {SERVER_DIR}/{SERVER_NAME}_cert.pem")
print(f"  Client: {CLIENT_DIR}/{CLIENT_NAME}_key.pem,  {CLIENT_DIR}/{CLIENT_NAME}_cert.pem")
