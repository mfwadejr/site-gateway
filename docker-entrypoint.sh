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

# --- Docker socket group access -------------------------------------------------------------
# A bind-mounted /var/run/docker.sock is typically owned root:docker on the host with mode
# 0660 -- readable only by root or members of that group. The app drops straight to an
# unprivileged PUID:PGID with no supplementary groups, so even a correctly mounted socket looks
# "not detected" to it. The Docker group's GID varies host to host (Unraid, Debian, Synology,
# etc. all differ), so rather than hardcode one, read it directly off the mounted socket while
# still root, make sure a local group with that GID exists and the app user is a member of it,
# then hand su-exec a username instead of a bare uid:gid so it picks up supplementary groups via
# initgroups() -- the uid:gid form only ever sets the one primary group. Every step here is
# best-effort: if anything fails, app_exec_target stays the original "$app_uid:$app_gid" and the
# app starts exactly as it always has, just without Docker integration -- same as an unmounted
# socket, never worse.
app_exec_target="$app_uid:$app_gid"
docker_socket="/var/run/docker.sock"
if [ -S "$docker_socket" ]; then
  docker_gid="$(stat -c '%g' "$docker_socket" 2>/dev/null || true)"
  if [ -n "$docker_gid" ] && [ "$docker_gid" != "$app_gid" ]; then
    docker_group_name="$(getent group "$docker_gid" 2>/dev/null | cut -d: -f1 || true)"
    if [ -z "$docker_group_name" ]; then
      addgroup -g "$docker_gid" sgdockersock 2>/dev/null || true
      docker_group_name="$(getent group "$docker_gid" 2>/dev/null | cut -d: -f1 || true)"
    fi
    if [ -n "$docker_group_name" ]; then
      app_group_name="$(getent group "$app_gid" 2>/dev/null | cut -d: -f1 || true)"
      if [ -z "$app_group_name" ]; then
        addgroup -g "$app_gid" sgapp 2>/dev/null || true
        app_group_name="$(getent group "$app_gid" 2>/dev/null | cut -d: -f1 || true)"
      fi
      if [ -n "$app_group_name" ] && ! getent passwd "$app_uid" >/dev/null 2>&1; then
        adduser -D -H -u "$app_uid" -G "$app_group_name" sgapp 2>/dev/null || true
      fi
      app_user_name="$(getent passwd "$app_uid" 2>/dev/null | cut -d: -f1 || true)"
      if [ -n "$app_user_name" ]; then
        addgroup "$app_user_name" "$docker_group_name" 2>/dev/null || true
        if id -nG "$app_user_name" 2>/dev/null | grep -qw "$docker_group_name"; then
          app_exec_target="$app_user_name"
        fi
      fi
    fi
  fi
fi

su-exec "$app_uid:$app_gid" caddy run --config "$caddyfile" --adapter caddyfile &
caddy_pid=$!
su-exec "$app_exec_target" "$@" &
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
