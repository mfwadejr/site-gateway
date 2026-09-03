#!/bin/sh
set -eu

app_uid="${PUID:-1000}"
app_gid="${PGID:-1000}"

case "$app_uid:$app_gid" in
  *[!0-9:]*|:*|*:) echo "PUID and PGID must be numeric." >&2; exit 1 ;;
esac

data_root="${DATA_DIR:-/data}"
mkdir -p "$data_root/sites" "$data_root/.uploads" "$data_root/caddy/config" "$data_root/icons" "$data_root/logs" "$data_root/default-site" "$data_root/database" "$data_root/migrations" "$data_root/backups" "$data_root/certificates/custom" "$data_root/certificates/managed" "$data_root/certificates/exports"

# Preserve legacy certificate storage before Caddy starts using the unified location.
if [ -d "$data_root/custom-certificates" ] && [ -z "$(find "$data_root/certificates/custom" -mindepth 1 -print -quit 2>/dev/null)" ]; then cp -a "$data_root/custom-certificates/." "$data_root/certificates/custom/"; fi
if [ -d "$data_root/caddy/data/caddy" ] && [ -z "$(find "$data_root/certificates/managed" -mindepth 1 -print -quit 2>/dev/null)" ]; then cp -a "$data_root/caddy/data/caddy/." "$data_root/certificates/managed/"; fi
chown -R "$app_uid:$app_gid" "${DATA_DIR:-/data}"
chmod 700 "$data_root/database" "$data_root/backups" "$data_root/certificates/custom" "$data_root/certificates/managed"

caddyfile="${DATA_DIR:-/data}/caddy/Caddyfile"
if [ ! -f "$caddyfile" ]; then
  printf '%s\n' '{' '  admin localhost:2019' '  persist_config off' "  storage file_system $data_root/certificates/managed" '}' '' ':80 {' '  respond "Site Gateway is ready." 404' '}' > "$caddyfile"
  chown "$app_uid:$app_gid" "$caddyfile"
fi
if ! grep -q '^[[:space:]]*storage file_system ' "$caddyfile"; then
  sed -i "/^[[:space:]]*persist_config off/a\\  storage file_system $data_root/certificates/managed" "$caddyfile"
fi

export XDG_DATA_HOME="${DATA_DIR:-/data}/certificates/managed"
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
