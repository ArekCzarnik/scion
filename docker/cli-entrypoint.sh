#!/bin/sh
# Runs `scion` as the configured service principal. Tokens expire and HOME is throwaway, so each
# run logs in first. `import` dispatches to scion-import, which logs in by itself.
set -eu

if [ -z "${SCION_SERVICE_SECRET:-}" ] && [ -r "${SCION_SERVICE_SECRET_FILE:-}" ]; then
  SCION_SERVICE_SECRET=$(cat "$SCION_SERVICE_SECRET_FILE")
  export SCION_SERVICE_SECRET
fi

case "${1:-}" in
  import)
    shift
    exec scion-import "$@"
    ;;
  "" | -h | --help | help | -V | --version | login)
    exec scion "$@"
    ;;
esac

if [ -z "${SCION_TOKEN:-}" ] && [ -n "${SCION_SERVICE_SECRET:-}" ]; then
  scion login --service "$SCION_SERVICE_NAME" >/dev/null
fi

exec scion "$@"
