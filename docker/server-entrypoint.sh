#!/bin/sh
# Prepares the scion-server container: on first start it generates everything the server needs
# but compose cannot provide (keys, TLS, service secrets), then execs the server.
#
#   /var/lib/scion/secrets  signing key, CA key, TLS key and certificate (server only)
#   /var/lib/scion/client   CA certificate and agent secret (shared with CLI containers)
#   /var/lib/scion/admin    admin secret (only for clients that import or redact)
#
# Existing files are kept. The certificate is reissued from the same CA when SCION_TLS_HOSTS
# changes, so clients keep trusting the server.
set -eu

secrets=/var/lib/scion/secrets
client=/var/lib/scion/client
admin=/var/lib/scion/admin
hosts=${SCION_TLS_HOSTS:-localhost,127.0.0.1,scion-server}

umask 077

new_secret() {
  if [ ! -f "$1" ]; then
    echo "scion: generating $(basename "$1")" >&2
    (umask 022 && openssl rand -hex 32 | tr -d '\n' >"$1")
  fi
}

sha256_of() {
  sha256sum <"$1" | cut -d' ' -f1
}

if [ ! -f "$secrets/signing.ed25519.pem" ]; then
  echo "scion: generating the token signing key" >&2
  openssl genpkey -algorithm ED25519 -out "$secrets/signing.ed25519.pem"
fi

if [ ! -f "$secrets/ca.key" ]; then
  echo "scion: generating the private CA" >&2
  # rustls rejects a CA certificate used as the server certificate, hence two levels.
  openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 3650 \
    -subj "/CN=Scion Compose CA" \
    -addext "basicConstraints=critical,CA:TRUE" -addext "keyUsage=critical,keyCertSign" \
    -keyout "$secrets/ca.key" -out "$secrets/ca.crt" 2>/dev/null
  rm -f "$secrets/tls.crt"
fi

if [ ! -f "$secrets/tls.crt" ] || [ "$(cat "$secrets/tls.hosts" 2>/dev/null)" != "$hosts" ]; then
  echo "scion: issuing the TLS certificate for $hosts" >&2
  san=
  for host in $(printf %s "$hosts" | tr ',' ' '); do
    case "$host" in
      *:*) entry="IP:$host" ;;
      *[!0-9.]*) entry="DNS:$host" ;;
      *) entry="IP:$host" ;;
    esac
    san="$san${san:+,}$entry"
  done
  printf 'subjectAltName=%s\nextendedKeyUsage=serverAuth\n' "$san" >"$secrets/tls.ext"
  openssl req -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -subj "/CN=scion-server" \
    -keyout "$secrets/tls.key" -out "$secrets/tls.csr" 2>/dev/null
  openssl x509 -req -days 3650 -in "$secrets/tls.csr" -extfile "$secrets/tls.ext" \
    -CA "$secrets/ca.crt" -CAkey "$secrets/ca.key" \
    -CAserial "$secrets/ca.srl" -CAcreateserial \
    -out "$secrets/tls.crt" 2>/dev/null
  rm -f "$secrets/tls.csr" "$secrets/tls.ext"
  printf %s "$hosts" >"$secrets/tls.hosts"
fi

# CLI containers run under arbitrary user ids, so these files are world-readable; access is
# decided by who mounts the volume.
new_secret "$client/agent.secret"
new_secret "$admin/admin.secret"
install -m 0644 "$secrets/ca.crt" "$client/ca.crt"

SCION_AGENT_SECRET_SHA256=$(sha256_of "$client/agent.secret")
SCION_ADMIN_SECRET_SHA256=$(sha256_of "$admin/admin.secret")
export SCION_AGENT_SECRET_SHA256 SCION_ADMIN_SECRET_SHA256

exec "$@"
