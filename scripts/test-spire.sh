#!/usr/bin/env bash
# Runs the gated external_spiffe_* tests against a real SPIRE server and agent, without Docker.
#
#   scripts/test-spire.sh            start SPIRE in a temporary directory, test, stop it
#   SPIRE_BIN=/path/bin scripts/...  use spire-server and spire-agent from that directory
#   scripts/test-spire.sh --serve    start SPIRE and wait, printing the variables to set
#
# Linux only: the agent identifies the test process through its Unix peer credentials.
set -euo pipefail
cd "$(dirname "$0")/.."

SERVE=0
case "${1:-}" in
  --serve) SERVE=1 ;;
  "") ;;
  -h|--help) sed -n '2,8p' "$0"; exit 0 ;;
  *) echo "usage: $0 [--serve]" >&2; exit 2 ;;
esac

BIN="${SPIRE_BIN:+$SPIRE_BIN/}"
command -v "${BIN}spire-server" >/dev/null || {
  echo "spire-server not found: set SPIRE_BIN or add it to PATH" >&2
  exit 1
}

TRUST_DOMAIN=example.org
WORKLOAD_ID="spiffe://$TRUST_DOMAIN/ns/ci/sa/tester"
DIR="$(mktemp -d "${TMPDIR:-/tmp}/scion-spire.XXXXXX")"
SERVER_SOCKET="$DIR/server/api.sock"
AGENT_SOCKET="$DIR/agent/api.sock"
PIDS=()

cleanup() {
  kill "${PIDS[@]}" 2>/dev/null || true
  wait "${PIDS[@]}" 2>/dev/null || true
  rm -rf "$DIR"
}
trap cleanup EXIT

spire_server() { "${BIN}spire-server" "$@"; }

wait_for() {
  local what="$1"
  shift
  for _ in $(seq 1 100); do
    "$@" >/dev/null 2>&1 && return 0
    sleep 0.2
  done
  echo "timed out waiting for $what; logs are in $DIR" >&2
  exit 1
}

mkdir -p "$DIR/server" "$DIR/agent"
cat >"$DIR/server.conf" <<EOF
server {
  bind_address = "127.0.0.1"
  bind_port = "18081"
  socket_path = "$SERVER_SOCKET"
  trust_domain = "$TRUST_DOMAIN"
  data_dir = "$DIR/server"
  log_level = "WARN"
  default_jwt_svid_ttl = "5m"
}
plugins {
  DataStore "sql" {
    plugin_data {
      database_type = "sqlite3"
      connection_string = "$DIR/server/datastore.sqlite3"
    }
  }
  NodeAttestor "join_token" { plugin_data {} }
  KeyManager "memory" { plugin_data {} }
}
EOF
"${BIN}spire-server" run -config "$DIR/server.conf" >"$DIR/server.log" 2>&1 &
PIDS+=($!)
wait_for "spire-server" spire_server healthcheck -socketPath "$SERVER_SOCKET"

JOIN_TOKEN="$(spire_server token generate -socketPath "$SERVER_SOCKET" \
  -spiffeID "spiffe://$TRUST_DOMAIN/node" | awk '{print $2}')"
cat >"$DIR/agent.conf" <<EOF
agent {
  data_dir = "$DIR/agent"
  log_level = "WARN"
  server_address = "127.0.0.1"
  server_port = "18081"
  socket_path = "$AGENT_SOCKET"
  trust_domain = "$TRUST_DOMAIN"
  insecure_bootstrap = true
}
plugins {
  NodeAttestor "join_token" { plugin_data {} }
  KeyManager "memory" { plugin_data {} }
  WorkloadAttestor "unix" { plugin_data {} }
}
EOF
"${BIN}spire-agent" run -config "$DIR/agent.conf" -joinToken "$JOIN_TOKEN" >"$DIR/agent.log" 2>&1 &
PIDS+=($!)
wait_for "spire-agent" "${BIN}spire-agent" healthcheck -socketPath "$AGENT_SOCKET"

spire_server entry create -socketPath "$SERVER_SOCKET" \
  -parentID "spiffe://$TRUST_DOMAIN/node" \
  -spiffeID "$WORKLOAD_ID" \
  -selector "unix:uid:$(id -u)" >/dev/null
wait_for "the workload identity" "${BIN}spire-agent" api fetch jwt \
  -audience probe -socketPath "$AGENT_SOCKET"

spire_server bundle show -socketPath "$SERVER_SOCKET" -format spiffe >"$DIR/bundle.json"

cat >"$DIR/rotate.sh" <<EOF
#!/usr/bin/env bash
set -euo pipefail
server="\$(command -v "${BIN}spire-server")"
"\$server" localauthority jwt prepare -socketPath "$SERVER_SOCKET" >/dev/null
prepared="\$("\$server" localauthority jwt show -socketPath "$SERVER_SOCKET" |
  awk '/Prepared JWT authority/ { getline; print \$3 }')"
"\$server" localauthority jwt activate -socketPath "$SERVER_SOCKET" -authorityID "\$prepared" >/dev/null
"\$server" bundle show -socketPath "$SERVER_SOCKET" -format spiffe >"$DIR/bundle.json.new"
mv "$DIR/bundle.json.new" "$DIR/bundle.json"
EOF
chmod +x "$DIR/rotate.sh"

export SCION_TEST_SPIRE_SOCKET="unix://$AGENT_SOCKET"
export SCION_TEST_SPIRE_BUNDLE="$DIR/bundle.json"
export SCION_TEST_SPIRE_ID="$WORKLOAD_ID"
export SCION_TEST_SPIRE_TRUST_DOMAIN="$TRUST_DOMAIN"
export SCION_TEST_SPIRE_ROTATE="$DIR/rotate.sh"

if [ "$SERVE" = 1 ]; then
  echo "SPIRE is running; logs are in $DIR"
  env | grep '^SCION_TEST_SPIRE_' | sed 's/^/export /'
  echo "Press Ctrl-C to stop."
  wait
else
  cargo test -p scion-cli --test cli_spiffe_external -- --nocapture
fi
