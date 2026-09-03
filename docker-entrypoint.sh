#!/bin/sh
set -eu

app_uid="${PUID:-1000}"
app_gid="${PGID:-1000}"

case "$app_uid:$app_gid" in
  *[!0-9:]*|:*|*:) echo "PUID and PGID must be numeric." >&2; exit 1 ;;
esac

mkdir -p "${DATA_DIR:-/data}/sites" "${DATA_DIR:-/data}/.uploads" "${DATA_DIR:-/data}/caddy/data" "${DATA_DIR:-/data}/caddy/config" "${DATA_DIR:-/data}/icons" "${DATA_DIR:-/data}/logs" "${DATA_DIR:-/data}/default-site" "${DATA_DIR:-/data}/custom-certificates" "${BACKUP_DIR:-${DATA_DIR:-/data}/backups}"
chown -R "$app_uid:$app_gid" "${DATA_DIR:-/data}"
if [ "${BACKUP_DIR:-${DATA_DIR:-/data}/backups}" != "${DATA_DIR:-/data}/backups" ]; then chown -R "$app_uid:$app_gid" "${BACKUP_DIR}"; fi

caddyfile="${DATA_DIR:-/data}/caddy/Caddyfile"
if [ ! -f "$caddyfile" ]; then
  printf '%s\n' '{' '  admin localhost:2019' '  persist_config off' '}' '' ':80 {' '  respond "Site Gateway is ready." 404' '}' > "$caddyfile"
  chown "$app_uid:$app_gid" "$caddyfile"
fi

export XDG_DATA_HOME="${DATA_DIR:-/data}/caddy/data"
export XDG_CONFIG_HOME="${DATA_DIR:-/data}/caddy/config"

su-exec "$app_uid:$app_gid" caddy run --config "$caddyfile" --adapter caddyfile &
caddy_pid=$!
su-exec "$app_uid:$app_gid" "$@" &
app_pid=$!

shutdown() {
  kill -TERM "$app_pid" "$caddy_pid" 2>/dev/null || true
  wait "$app_pid" "$caddy_pid" 2>/dev/null || true
}
trap shutdown TERM INT

wait "$app_pid"
status=$?
kill -TERM "$caddy_pid" 2>/dev/null || true
wait "$caddy_pid" 2>/dev/null || true
exit "$status"
