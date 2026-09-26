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
    <a href="https://github.com/mfwadejr/site-gateway/actions/workflows/container.yml"><img alt="Container build" src="https://github.com/mfwadejr/site-gateway/actions/workflows/container.yml/badge.svg"></a>
    <img alt="Docker" src="https://img.shields.io/badge/Docker-ready-2496ED?logo=docker&logoColor=white">
    <img alt="Architectures" src="https://img.shields.io/badge/platform-amd64%20%7C%20arm64-5965F2">
    <img alt="Caddy" src="https://img.shields.io/badge/powered%20by-Caddy-1F88C0">
    <img alt="Version" src="https://img.shields.io/badge/version-0.16.104-62E6A7">
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

I didn't set out to build a reverse-proxy manager. I just wanted to host one website without hand-editing a Caddyfile or Nginx config every time I needed a domain and a certificate pointed at something. Every option I found was either too raw (edit the config, reload, hope it works) or way more than I needed for one site.

Once that one site was working — and it only took a few clicks — I realized the same thing applied to everything else I was running. Proxying Plex, forwarding a port for a hosted service, redirecting a domain, renewing a certificate — every one of those was its own manual chore in whatever proxy setup I already had. What I actually wanted wasn't a nicer way to host a website. It was a replacement for my whole reverse-proxy setup, with one dashboard that handled all of it the same easy way.

That's Site Gateway now: one container, one dashboard, for static sites, proxy routes, redirects, raw TCP/UDP streams, TLS, and access control — with [Caddy](https://caddyserver.com/) doing the actual routing and certificates underneath. I built it so someone who's never touched a Caddyfile can point a domain at an app in a couple clicks, and someone who's run Nginx Proxy Manager or Traefik for years won't feel like anything's missing.

The goal for day-to-day use is three steps. Hosting a site, three steps. Setting up a proxy host, three steps. That's for the stuff you'll do over and over. It doesn't apply to the initial install below — that's honestly closer to five steps, because getting Docker, your `.env`, and your first admin account right matters more than hitting a number.

It's narrower than a general-purpose proxy manager on purpose. You tell it what you want — a site, a proxy target, a redirect, a port forward — and it writes and reloads the actual gateway config for you. No Caddyfile required.

## What you get

| Hosted Sites | Proxy Hosts | Redirect Hosts | Streaming Hosts |
| --- | --- | --- | --- |
| Upload a ZIP or `index.html` and publish static files on a domain and/or a direct port | Point a domain at Plex, Jellyfin, Vaultwarden, or any HTTP app — TLS, HSTS, and headers included | Send one or more domains to a canonical destination with 301/302/307/308 | Forward raw TCP/UDP ports straight to a service — game servers, SSH, anything that isn't HTTP |

- **Automatic HTTPS** — Caddy issues and renews public certificates; internal, HTTP-only, and uploaded custom-certificate modes are also supported.
- **Live dashboard** — gateway/HTTP/HTTPS/storage health, hosted and proxy counts, certificate status, and throughput at a glance, plus a live resource panel (CPU, memory, swap, disk, network, uptime) reading real container-scoped cgroup v2 stats, not host-wide numbers, and auto-refreshing while the page is open.
- **Access Lists** — reusable login/network policies combining accounts, groups, and IP/CIDR rules across any host.
- **Two-factor authentication** — TOTP-based MFA for administrator and user accounts, with recovery codes, plus an administrator-side override to disable a locked-out user's 2FA when they've lost their authenticator and used up their recovery codes.
- **Users, groups, and roles** — Administrator and Standard User roles, with account lifecycle controls.
- **API access tokens** — issue scoped (full-access or read-only), optionally expiring bearer tokens for scripts and integrations, revocable at any time.
- **Backups** — configuration or complete `.sgbackup` archives, downloadable, importable, schedulable, and optionally AES-256-GCM encrypted.
- **Certificates page** — issuer, expiration, days remaining, and renewal health for every managed and uploaded certificate.
- **Performance and logs** — per-domain request throughput, response times, and rotating access/activity logs, including a System page (Administration) with the same live resource panel as the Dashboard, environment/integration status, gateway sync, scheduled jobs, storage usage, and version/database/public IP details.
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
| `DATA_DIR_LIMIT_GB` | empty | Optional display-only allowance for the System tab's Disk stat (e.g. a smaller dedicated share); usage/free space still come from the real volume |
| `BACKUP_PASSWORD` | empty | Encryption password used only when encrypted scheduled backups are enabled |
| `PUID` / `PGID` | `1000` / `1000` | User/group the container writes files as (Unraid: `99`/`100`) |
| `ACME_EMAIL` | empty | Optional certificate account email |

At startup, the container creates the complete `/data` hierarchy, applies `PUID`/`PGID` ownership, then drops root privileges. Configuration lives in SQLite at `/data/database/site-gateway.sqlite`; hosted files live under `/data/sites`; backups under `/data/backups`; certificates under `/data/certificates`.

## Unraid

1. Add the container from **Docker → Add Container** using the image `ghcr.io/mfwadejr/site-gateway:latest`, or search Community Applications once a template is published.
2. Map ports `80`, `443` (TCP+UDP), `8080`, and `9000-9099` as above, plus any Streaming Host ports you plan to use.
3. Map one path, e.g. `/mnt/user/appdata/site-gateway:/data`.
4. Set `PUID=99` and `PGID=100` so the container writes to `/data` as the `nobody`/`users` account Unraid expects.
5. Set `ADMIN_PASSWORD` and `SESSION_SECRET`, then start the container and open `http://UNRAID-IP:8080`.

For automatic image-based upgrades, Unraid's **Update Container** action pulls the newest `latest` image; if you use Watchtower, `compose.release.yaml` includes its opt-in label.

## ZimaOS

The simplest path is [`compose.zimaos.yaml`](compose.zimaos.yaml) — a ready-to-import file with the `x-casaos` metadata ZimaOS's app installer and App Store use for the icon, title, and port mapping.

1. In ZimaOS, go to **Docker → Install a Customized App**, and paste or select `compose.zimaos.yaml`.
2. Before starting it, edit `ADMIN_PASSWORD` and `SESSION_SECRET` in the environment fields.
3. Confirm the data path — it defaults to `/DATA/AppData/site-gateway` — and start the app.
4. Open `http://ZIMAOS-IP:8080`.

Prefer a plain Compose file instead? `compose.yaml` (build from source) and `compose.release.yaml` (pull the published image) both work the same way:

1. Copy this folder into ZimaOS storage, e.g. `/DATA/AppData/site-gateway/app`.
2. Point the Compose volume at `/DATA/AppData/site-gateway/data:/data`.
3. Set `ADMIN_PASSWORD` and `SESSION_SECRET` (and `PUID`/`PGID` if needed — ZimaOS typically uses `1000:1000`).
4. Import through ZimaOS's custom app / Compose import option, or run it from the terminal:

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

See [ROADMAP.md](ROADMAP.md) for what's shipped and what's next, or [CHANGELOG.md](CHANGELOG.md) for the full per-release history.

## License

MIT — see [LICENSE](LICENSE).
