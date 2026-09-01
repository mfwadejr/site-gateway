<div align="center">
  <img src="product-icon-v1.png" alt="Site Gateway icon" width="180">
  <h1>Site Gateway</h1>
  <p><strong>Host. Proxy. Secure.</strong></p>
  <p>A friendly, self-hosted gateway for websites, applications, domains, and automatic HTTPS.</p>
  <p>
    <a href="https://github.com/mfwadejr/site-gateway/actions/workflows/container.yml"><img alt="Container build" src="https://github.com/mfwadejr/site-gateway/actions/workflows/container.yml/badge.svg"></a>
    <img alt="Docker" src="https://img.shields.io/badge/Docker-ready-2496ED?logo=docker&logoColor=white">
    <img alt="Architectures" src="https://img.shields.io/badge/platform-amd64%20%7C%20arm64-5965F2">
    <img alt="Caddy" src="https://img.shields.io/badge/powered%20by-Caddy-1F88C0">
    <img alt="Public beta" src="https://img.shields.io/badge/status-public%20beta-62E6A7">
  </p>
  <p>
    <a href="#quick-start">Quick start</a> ·
    <a href="#domains-proxy-hosts-and-tls">Domains &amp; TLS</a> ·
    <a href="#unraid-beta-install">Unraid</a> ·
    <a href="#zimaos-beta-install">ZimaOS</a> ·
    <a href="ROADMAP.md">Roadmap</a>
  </p>
</div>

---

Site Gateway gives a home server one clear control panel for two jobs: publishing uploaded static sites and routing domains to applications already running on your network. Caddy handles the gateway, certificates, renewals, redirects, compression, and WebSocket forwarding behind the scenes.

| Publish | Route | Protect | Operate |
| --- | --- | --- | --- |
| Upload a ZIP or `index.html` | Proxy domains to LAN apps or containers | Automatic HTTPS certificates and renewal | Enable, disable, replace, and delete from one dashboard |
| Assign direct testing ports | Host multiple domains on ports 80/443 | Optional HSTS and HTTPS redirects | Persistent `/data` storage with PUID/PGID support |

> [!NOTE]
> Site Gateway is intentionally simpler than a general-purpose proxy manager. You provide the site or destination; the guided interface writes and safely reloads the gateway configuration.

## Beta features

- Password-protected, responsive admin dashboard
- Installed-version reporting in the dashboard
- Create a site from a ZIP archive or a single `index.html`
- One independently enabled/disabled port per site
- Caddy gateway on ports 80 and 443
- Domain routing and automatic HTTPS for hosted sites
- Reverse proxy hosts for containers, LAN services, and applications
- Automatic certificate renewal and HTTP-to-HTTPS redirects
- Replace a site's files without recreating it
- Delete sites and their stored files
- Persistent configuration and uploads under `/data`
- Path traversal protection for ZIP extraction and a 250 MB upload limit
- Clean shutdown and automatic site restart after a container restart

Hosted uploads remain static-only (HTML, CSS, JavaScript, images, fonts, and downloads). Dynamic applications can be connected as proxy hosts. Site Gateway does not execute uploaded PHP, Node, Python, or database code.

## Quick start

Requirements: Docker Engine with Docker Compose.

1. Edit `compose.yaml` and replace `change-this-password` with a strong password.
2. From this folder, run:

   ```bash
   docker compose up -d --build
   ```

3. Open `http://YOUR-SERVER-IP:8080`.
4. Sign in with `admin` and the password you chose.
5. Select **New site**, provide a name and unused port, then upload either:
   - a ZIP with `index.html` at its root; or
   - a single `index.html` file.
6. Open the site from its arrow button or visit `http://YOUR-SERVER-IP:PORT`.

The included Compose file publishes site ports 9000–9099. Docker cannot add a host port to an already-running container, so any site port must be included in the published range. Change `SITE_PORT_MIN`, `SITE_PORT_MAX`, and the Compose `ports` range together before starting the container if you want a different range.

For domain routing and automatic certificates, point the domain's DNS record at this server and forward public ports 80 and 443 to the container. If another reverse proxy already owns those ports, stop it or map Site Gateway to temporary alternate host ports for LAN testing; public ACME issuance will not work until 80/443 traffic reaches Site Gateway.

## Domains, proxy hosts, and TLS

Use **Hosted sites** for uploaded files. A domain is optional; when present, Caddy serves the site on ports 80/443 and automatically obtains and renews a public certificate. Direct site ports remain available for LAN testing.

Use **Proxy hosts** to connect a domain to an existing application such as `http://192.168.1.20:3000` or another container name and port. Caddy supplies the normal forwarded headers and supports WebSocket upgrades automatically.

Automatic HTTPS requires valid public DNS and inbound access to port 80 or 443. Caddy renews certificates automatically before expiration. HSTS is optional and should only be enabled after HTTPS works reliably.

## Install from the published image

Each push to `main` automatically publishes `ghcr.io/mfwadejr/site-gateway:latest` for both Intel/AMD and ARM64 servers. Copy `.env.example` to `.env`, replace the password and session secret, then run:

```bash
docker compose -f compose.release.yaml pull
docker compose -f compose.release.yaml up -d
```

To upgrade later:

```bash
docker compose -f compose.release.yaml pull
docker compose -f compose.release.yaml up -d
```

This recreates only the application container. Uploaded sites remain in the persistent data mount.

## ZIP layout

Preferred:

```text
my-site.zip
├── index.html
├── styles.css
├── app.js
└── images/
    └── logo.png
```

A ZIP containing one top-level folder is also accepted; Site Gateway unwraps that folder automatically.

## Unraid beta install

### Option A: Compose Manager

1. Install **Compose Manager** from Community Applications if it is not already present.
2. Copy this project folder to `/mnt/user/appdata/site-gateway/app`.
3. In `compose.yaml`, change the volume to `/mnt/user/appdata/site-gateway/data:/data`.
4. Set a strong `ADMIN_PASSWORD`. Optionally set a long random `SESSION_SECRET`.
5. Add the stack in Compose Manager and choose **Compose Up**.
6. Open `http://UNRAID-IP:8080`.

For automatic image-based upgrades, use `compose.release.yaml` instead. Unraid's **Update Container** action can pull the newest `latest` image. If you already use Watchtower, the release Compose file includes its opt-in label.

### Option B: build from the Unraid terminal

```bash
cd /mnt/user/appdata/site-gateway/app
docker compose up -d --build
```

If Unraid reports a port conflict, change the admin port mapping's left side (for example `8180:8080`) or choose a different site-port range. Allow the selected site ports through any LAN firewall.

## ZimaOS beta install

1. Copy this folder into ZimaOS storage, for example `/DATA/AppData/site-gateway/app`.
2. Change the Compose volume to `/DATA/AppData/site-gateway/data:/data`.
3. Set a strong `ADMIN_PASSWORD` and optionally `SESSION_SECRET`.
4. In the ZimaOS app interface, use its custom app / Compose import option and paste or select `compose.yaml`. If that option is unavailable in your release, use the terminal:

   ```bash
   cd /DATA/AppData/site-gateway/app
   docker compose up -d --build
   ```

5. Open `http://ZIMAOS-IP:8080`.

For simple upgrades, import `compose.release.yaml`; use ZimaOS's container update/recreate action whenever a new image is published. The `/data` mount keeps all sites during replacement.

## Migrating from Web Server

The product, repository, image, and default container are now named Site Gateway. Existing data does not need to move. Stop and remove the old container, then run the new image while mounting the existing folder:

```bash
docker stop web-server
docker rm web-server
docker pull ghcr.io/mfwadejr/site-gateway:latest
docker run -d --name site-gateway --restart unless-stopped \
  -p 8080:8080 -p 80:80 -p 443:443 -p 9000-9099:9000-9099 \
  -v /DATA/AppData/web-server:/data \
  -e ADMIN_USERNAME=admin \
  -e ADMIN_PASSWORD='YOUR_EXISTING_PASSWORD' \
  -e SESSION_SECRET='YOUR_EXISTING_SESSION_SECRET' \
  -e PUID=1000 -e PGID=1000 \
  ghcr.io/mfwadejr/site-gateway:latest
```

After confirming the sites appear, you may keep the legacy host folder or rename it to `/DATA/AppData/site-gateway` while the container is stopped and update the mount accordingly. Unraid users should retain `/mnt/user/appdata/web-server` as the template's Data path for the first upgraded launch.

## Configuration

| Variable | Default | Purpose |
|---|---:|---|
| `ADMIN_USERNAME` | `admin` | Dashboard login name |
| `ADMIN_PASSWORD` | `change-this-password` | Dashboard password; always change it |
| `SESSION_SECRET` | derived | Optional stable signing secret for login sessions |
| `ADMIN_PORT` | `8080` | Dashboard port inside the container |
| `SITE_PORT_MIN` | `9000` | Lowest allowed site port |
| `SITE_PORT_MAX` | `9099` | Highest allowed site port |
| `DATA_DIR` | `/data` | Persistent state location |
| `PUID` | `1000` | UID that owns and runs against persistent files |
| `PGID` | `1000` | GID that owns and runs against persistent files |
| `ACME_EMAIL` | empty | Optional certificate account email |

At startup, the container automatically creates `/data/sites` and `/data/.uploads`, applies `PUID`/`PGID` ownership, and then drops root privileges before starting the application. With the ZimaOS bind mount, these appear under `/DATA/AppData/site-gateway` on the host. Unraid commonly uses `PUID=99` and `PGID=100`; ZimaOS typically uses `1000:1000`.

## Backup and update

Back up the entire mounted `data` directory. It contains `sites.json` and every uploaded site.

To rebuild after pulling a new version:

```bash
docker compose up -d --build
```

Your sites remain intact because they live in the mounted data directory.

## Publishing updates

The GitHub Actions workflow builds and publishes a fresh multi-architecture container whenever code is pushed to `main`. A tag such as `v0.2.0` also produces a matching versioned image. The package starts private if the GitHub account's package defaults require it; make the `site-gateway` package public in GitHub package settings so Unraid and ZimaOS can pull without credentials.

## Security notes

- Change the default password before first use.
- Keep the dashboard on a trusted LAN or behind a trusted HTTPS reverse proxy/VPN. The beta dashboard itself serves plain HTTP.
- Do not expose the admin dashboard directly to the internet.
- Uploaded static JavaScript runs for visitors. Only publish files you trust.
- The container runs as the unprivileged `node` user and does not require access to the Docker socket.

## Troubleshooting

- **Site shows Error:** another process probably owns its port. Check `docker logs site-gateway`, then recreate the site on a free published port.
- **Site cannot be reached:** confirm the port is within the published Compose range and allowed through the server firewall.
- **Permission denied under `/data`:** make the host data directory writable by UID/GID 1000, or adjust ownership to match your environment.
- **Upload fails:** verify the file is below 250 MB and the extracted root contains `index.html`.
- **Dashboard port is busy:** change only the host side, such as `8180:8080`, then browse to port 8180.

## Beta roadmap

Good next additions are per-site access logs, certificate status reporting, drag-and-drop folder upload, rollback/history, health checks, access lists, and guided DNS diagnostics.
