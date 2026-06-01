#!/usr/bin/env bash
#
# generate_certs.sh -- one-time CA setup + per-node cert minting.
#
# Produces one CA (RSA 4096, self-signed, 3650d, CN=ROS2-CA) and, for each
# node name argument, a key (RSA 2048) + cert (signed by the CA, 365d,
# CN=<node_name>).  CN must match the ROS2 node name returned by
# Node.get_name().
#
# Usage:
#   ./generate_certs.sh camera_node lidar_node planner_node legacy_node
#
# Output directory defaults to ./certs (override with CERTS_DIR).
#
# Requires: openssl on PATH. No Python dependency.

set -euo pipefail

CERTS_DIR="${CERTS_DIR:-./certs}"

if [ "$#" -lt 1 ]; then
  echo "usage: $0 <node_name> [<node_name> ...]" >&2
  echo "  e.g. $0 camera_node lidar_node planner_node legacy_node" >&2
  exit 1
fi

command -v openssl >/dev/null 2>&1 || { echo "error: openssl not found on PATH" >&2; exit 1; }

mkdir -p "$CERTS_DIR"

CA_KEY="$CERTS_DIR/ca.key"
CA_CRT="$CERTS_DIR/ca.crt"

# ---------------------------------------------------------------------------
# Certificate Authority (create once; reused on subsequent runs)
# ---------------------------------------------------------------------------
if [ ! -f "$CA_KEY" ] || [ ! -f "$CA_CRT" ]; then
  echo "[CA] generating RSA 4096 CA key -> $CA_KEY"
  openssl genrsa -out "$CA_KEY" 4096

  echo "[CA] self-signing CA cert (3650d, CN=ROS2-CA) -> $CA_CRT"
  openssl req -x509 -new -nodes \
    -key "$CA_KEY" \
    -sha256 \
    -days 3650 \
    -subj "/CN=ROS2-CA" \
    -out "$CA_CRT"
else
  echo "[CA] reusing existing CA ($CA_CRT)"
fi

# ---------------------------------------------------------------------------
# Per-node key + cert
# ---------------------------------------------------------------------------
for NODE in "$@"; do
  NODE_KEY="$CERTS_DIR/$NODE.key"
  NODE_CSR="$CERTS_DIR/$NODE.csr"
  NODE_CRT="$CERTS_DIR/$NODE.crt"

  echo "[$NODE] generating RSA 2048 key -> $NODE_KEY"
  openssl genrsa -out "$NODE_KEY" 2048

  echo "[$NODE] creating CSR (CN=$NODE)"
  openssl req -new \
    -key "$NODE_KEY" \
    -subj "/CN=$NODE" \
    -out "$NODE_CSR"

  echo "[$NODE] signing cert with CA (365d) -> $NODE_CRT"
  # NOTE: OpenSSL >= 3.0 assigns a random serial and does not write ca.srl
  # (the spec's expected output lists it; that reflects OpenSSL <= 1.1). The
  # -CAserial flag below still produces ca.srl on older OpenSSL. Either way the
  # signed certs carry unique serials and verify against the CA.
  openssl x509 -req \
    -in "$NODE_CSR" \
    -CA "$CA_CRT" \
    -CAkey "$CA_KEY" \
    -CAserial "$CERTS_DIR/ca.srl" \
    -CAcreateserial \
    -sha256 \
    -days 365 \
    -out "$NODE_CRT"

  # Intermediate CSR must not linger.
  rm -f "$NODE_CSR"
done

echo "done. certs written to $CERTS_DIR/"
