<div align="center">
  <p>
    <img src="src/public/site-gateway-icon-approved.png" alt="Site Gateway icon" width="88">
  </p>
  <p>
    <img src="src/public/site-gateway-wordmark-approved.png" alt="Site Gateway" width="280">
  </p>
  <p><strong>Host. Proxy. Secure.</strong></p>
  <p>A friendly, self-hosted gateway for homelabs and small teams — publish static sites, reverse-proxy your apps, forward raw TCP/UDP streams, and manage TLS and access from one calm dashboard.</p>
  <p>
    <a href="https://github.com/mfwadejr/site-gateway2/actions/workflows/container.yml"><img alt="Container build" src="https://github.com/mfwadejr/site-gateway2/actions/workflows/container.yml/badge.svg"></a>
    <img alt="Docker" src="https://img.shields.io/badge/Docker-ready-2496ED?logo=docker&logoColor=white">
    <img alt="Architectures" src="https://img.shields.io/badge/platform-amd64%20%7C%20arm64-5965F2">
    <img alt="Caddy" src="https://img.shields.io/badge/powered%20by-Caddy-1F88C0">
    <img alt="Version" src="https://img.shields.io/badge/version-0.11.101-62E6A7">
  </p>
  <p>
    <a href="#why-site-gateway">Why Site Gateway</a> ·
    <a href="#what-you-get">What you get</a> ·
    <a href="#quick-start">Quick start</a> ·
    <a href="#configuration">Configuration</a> ·
    <a href="#unraid">Unraid</a> ·
    <a href="#zimaos">ZimaOS</a> ·
    <a href="ROADMAP.md">Roadmap</a>
  </p>
</div>

---

## Why Site Gateway

Most homelabs end up with the same problem: a handful of self-hosted apps, a couple of static sites, maybe a game server, and no clean way to expose any of it without hand-editing Nginx or Caddy configs every time something changes. Site Gateway is a single container that gives that setup one dashboard: point a domain at it, pick what you're publishing, and it handles routing, certificates, and renewal behind the scenes with [Caddy](https://caddyserver.com/).

It's intentionally narrower than a general-purpose proxy manager. You describe *what* you want (a site, a proxy target, a redirect, a raw port forward) and Site Gateway writes and safely reloads the underlying gateway configuration — no Caddyfile required.

## What you get

| Hosted Sites | Proxy Hosts | Redirect Hosts | Streaming Hosts |
| --- | --- | --- | --- |
| Upload a ZIP or `index.html` and publish static files on a domain and/or a direct port | Point a domain at Plex, Jellyfin, Vaultwarden, or any HTTP app — TLS, HSTS, and headers included | Send one or more domains to a canonical destination with 301/302/307/308 | Forward raw TCP/UDP ports straight to a service — game servers, SSH, anything that isn't HTTP |

- **Automatic HTTPS** — Caddy issues and renews public certificates; internal, HTTP-only, and uploaded custom-certificate modes are also supported.
- **Live dashboard** — gateway/HTTP/HTTPS/storage health, hosted and proxy counts, certificate status, throughput, uptime, memory, disk, and version info at a glance.
- **Access Lists** — reusable login/network policies combining accounts, groups, and IP/CIDR rules across any host.
- **Two-factor authentication** — TOTP-based MFA for administrator and user accounts, with recovery codes.
- **Users, groups, and roles** — Administrator and Standard User roles, with account lifecycle controls.
- **Backups** — configuration or complete `.sgbackup` archives, downloadable, importable, schedulable, and optionally AES-256-GCM encrypted.
- **Certificates page** — issuer, expiration, days remaining, and renewal health for every managed and uploaded certificate.
- **Performance and logs** — request throughput, response times, and rotating access/activity logs per host.
- **SQLite-backed persistence** — no external database container; everything lives under one `/data` volume.

Hosted uploads remain static-only (HTML, CSS, JS, images, fonts, downloads). Dynamic applications are connected as Proxy Hosts instead — Site Gateway does not execute uploaded PHP, Node, Python, or database code.

## Quick start

Requirements: Docker Engine with Docker Compose, and ports 80/443 free on the host (plus 8080 for the dashboard).

1. Copy `.env.example` to `.env` and set `ADMIN_PASSWORD` and `SESSION_SECRET`.
2. Pull and start the published image:

   ```bash
   docker compose -f compose.release.yaml pull
   docker compose -f compose.release.yaml up -d
   ```

3. Open `http://YOUR-SERVER-IP:8080` and sign in with `admin` and the password you set.
4. Finish first-time setup (you'll be asked to confirm or change the display name, username, and password).
5. Create your first route from the dashboard — Hosted, Proxy, Redirect, or Streaming.

Prefer to build from source instead of pulling the image? Use `compose.yaml` and `docker compose up -d --build`.

The included Compose files publish site ports 9000–9099 for direct-LAN access to Hosted Sites. Docker can't add a host port to an already-running container, so change `SITE_PORT_MIN`, `SITE_PORT_MAX`, and the Compose `ports` range together, before starting the container, if you want a different range. The same applies to Streaming Hosts — publish the TCP/UDP port you plan to use before creating the route in the dashboard.

For domain routing and automatic certificates, point the domain's DNS record at this server and forward public ports 80 and 443 to the container. If another reverse proxy already owns those ports, stop it or use temporary alternate host ports for LAN testing — public ACME issuance won't work until 80/443 traffic actually reaches Site Gateway.

## Domains, proxy hosts, and TLS

Use **Hosted Sites** for uploaded files. A domain is optional; when present, Caddy serves the site on ports 80/443 and automatically obtains and renews a public certificate. Direct site ports remain available for LAN testing.

Use **Proxy Hosts** to connect a domain to an existing application, such as `http://192.168.1.20:3000` or another container's name and port. Caddy supplies the standard forwarded headers and supports WebSocket upgrades automatically.

Use **Streaming Hosts** for anything that isn't HTTP — game servers, SSH, or other raw TCP/UDP services. These need their port published in Compose up front, since Docker can't add ports to a running container.

Automatic HTTPS requires valid public DNS and inbound access to port 80 or 443. HSTS is optional and should only be enabled after HTTPS is confirmed working.

## Configuration

| Variable | Default | Purpose |
|---|---:|---|
| `ADMIN_USERNAME` | `admin` | Bootstrap dashboard login name |
| `ADMIN_PASSWORD` | — | Bootstrap dashboard password; **required**, always change it |
| `SESSION_SECRET` | — | **Required.** Any random string; rotating it signs everyone out |
| `ADMIN_PORT` | `8080` | Dashboard port inside the container |
| `SITE_PORT_MIN` / `SITE_PORT_MAX` | `9000` / `9099` | Direct-LAN port range Hosted Sites can bind to |
| `DATA_DIR` | `/data` | Persistent state location |
| `BACKUP_PASSWORD` | empty | Encryption password used only when encrypted scheduled backups are enabled |
| `PUID` / `PGID` | `1000` / `1000` | User/group the container writes files as (Unraid: `99`/`100`) |
| `ACME_EMAIL` | empty | Optional certificate account email |

At startup, the container creates the complete `/data` hierarchy, applies `PUID`/`PGID` ownership, then drops root privileges. Configuration lives in SQLite at `/data/database/site-gateway.sqlite`; hosted files live under `/data/sites`; backups under `/data/backups`; certificates under `/data/certificates`.

## Unraid

1. Add the container from **Docker → Add Container** using the image `ghcr.io/mfwadejr/site-gateway2:latest`, or search Community Applications once a template is published.
2. Map ports `80`, `443` (TCP+UDP), `8080`, and `9000-9099` as above, plus any Streaming Host ports you plan to use.
3. Map one path, e.g. `/mnt/user/appdata/site-gateway:/data`.
4. Set `PUID=99` and `PGID=100` so the container writes to `/data` as the `nobody`/`users` account Unraid expects.
5. Set `ADMIN_PASSWORD` and `SESSION_SECRET`, then start the container and open `http://UNRAID-IP:8080`.

For automatic image-based upgrades, Unraid's **Update Container** action pulls the newest `latest` image; if you use Watchtower, `compose.release.yaml` includes its opt-in label.

## ZimaOS

1. Copy this folder into ZimaOS storage, e.g. `/DATA/AppData/site-gateway/app`.
2. Point the Compose volume at `/DATA/AppData/site-gateway/data:/data`.
3. Set `ADMIN_PASSWORD` and `SESSION_SECRET` (and `PUID`/`PGID` if needed — ZimaOS typically uses `1000:1000`).
4. Import `compose.yaml` (or `compose.release.yaml` for image-based upgrades) through ZimaOS's custom app / Compose import option, or run it from the terminal:

   ```bash
   cd /DATA/AppData/site-gateway/app
   docker compose up -d --build
   ```

5. Open `http://ZIMAOS-IP:8080`. Use ZimaOS's container update/recreate action whenever a new image is published — the `/data` mount keeps all sites during replacement.

## Backup and update

Open **Administration → Backup & restore** to create a Configuration or Complete backup. Manual backups download to the browser; scheduled backups are stored under `/data/backups` and can be AES-256-GCM encrypted when `BACKUP_PASSWORD` is set. A Complete backup contains a consistent SQLite snapshot, portable JSON recovery data, hosted files, local icons, custom fallback assets, and certificate storage. Because certificate backups contain private keys, encryption is strongly recommended.

Before restoring, Site Gateway checks the archive manifest, creates a complete pre-restore safety backup, then reloads and validates the resulting configuration.

To upgrade:

```bash
docker compose -f compose.release.yaml pull
docker compose -f compose.release.yaml up -d
```

This recreates only the application container — your sites, certificates, and configuration remain in the mounted data directory.

## Security notes

- Use a unique bootstrap password during installation, then finish first-time setup to finalize the persistent administrator account.
- Enable two-factor authentication on administrator accounts.
- Keep the dashboard on a trusted LAN or behind a trusted HTTPS reverse proxy/VPN — don't expose the admin dashboard directly to the internet.
- Uploaded static JavaScript runs for visitors; only publish files you trust.
- The container starts as root only to apply `PUID`/`PGID` ownership and grant Caddy `cap_net_bind_service`, then drops both the Node app and Caddy to the unprivileged `PUID:PGID` user. It does not require access to the Docker socket.

## Troubleshooting

- **Site shows Error:** another process probably owns its port. Check `docker logs site-gateway`, then recreate the site on a free published port.
- **Site cannot be reached:** confirm the port is within the published Compose range and allowed through the server firewall.
- **Permission denied under `/data`:** make the host data directory writable by the configured `PUID`/`PGID`.
- **Upload fails:** verify the file is below 250 MB and the extracted root contains `index.html`.
- **Dashboard port is busy:** change only the host side, e.g. `8180:8080`, then browse to port 8180.
- **Streaming Host has no traffic:** confirm the TCP/UDP port is published in Compose *before* creating the route — Docker can't add ports to a running container.

## Roadmap

See [ROADMAP.md](ROADMAP.md) for what's shipped and what's next.

## License

MIT — see [LICENSE](LICENSE).
