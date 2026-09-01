#!/bin/sh
set -eu

app_uid="${PUID:-1000}"
app_gid="${PGID:-1000}"

case "$app_uid:$app_gid" in
  *[!0-9:]*|:*|*:) echo "PUID and PGID must be numeric." >&2; exit 1 ;;
esac

mkdir -p "${DATA_DIR:-/data}/sites" "${DATA_DIR:-/data}/.uploads"
chown -R "$app_uid:$app_gid" "${DATA_DIR:-/data}"

exec su-exec "$app_uid:$app_gid" "$@"
