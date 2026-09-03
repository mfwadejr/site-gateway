<div align="center">
  <img src="src/public/icon.png" alt="Site Gateway icon" width="180">
  <h1>Site Gateway</h1>
  <p><strong>Host. Proxy. Secure.</strong></p>
  <p>A friendly, self-hosted gateway for websites, applications, domains, and automatic HTTPS.</p>
  <p>
    <a href="https://github.com/mfwadejr/site-gateway/actions/workflows/container.yml"><img alt="Container build" src="https://github.com/mfwadejr/site-gateway/actions/workflows/container.yml/badge.svg"></a>
    <img alt="Docker" src="https://img.shields.io/badge/Docker-ready-2496ED?logo=docker&logoColor=white">
    <img alt="Architectures" src="https://img.shields.io/badge/platform-amd64%20%7C%20arm64-5965F2">
    <img alt="Caddy" src="https://img.shields.io/badge/powered%20by-Caddy-1F88C0">
    <img alt="Public alpha" src="https://img.shields.io/badge/status-public%20alpha-FFBF69">
  </p>
  <p>
    <a href="#quick-start">Quick start</a> ·
    <a href="#domains-proxy-hosts-and-tls">Domains &amp; TLS</a> ·
    <a href="#unraid-alpha-install">Unraid</a> ·
    <a href="#zimaos-alpha-install">ZimaOS</a> ·
    <a href="INSTALL-v0.8.0-alpha.2.md">v0.8 installation guide</a> ·
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

## Alpha features

- Password-protected, responsive dashboard with live gateway health
- Hosted-site, proxy-host, TLS-domain, and attention totals at a glance
- Runtime uptime, memory, persistent-data size, disk space, and installed versions
- Recent configuration activity for the current container session
- Confirmed Caddy, HTTP port 80, and HTTPS port 443 health checks with manual and automatic refresh
- Searchable Dashboard Icons picker with validated local storage under `/data/icons`
- Consistent two-letter icon fallbacks for hosted sites and proxy hosts
- Create a site from a ZIP archive or a single `index.html`
- One independently enabled/disabled port per site
- Caddy gateway on ports 80 and 443
- Domain routing and automatic HTTPS for hosted sites
- Reverse proxy hosts for containers, LAN services, and applications
- Redirect Hosts with 301, 302, 307, and 308 responses and optional path preservation
- Reusable Access Lists with LAN/CIDR rules and a themed username/password sign-in page
- Collapsible Proxy Host controls for custom locations, headers, compression, upstream TLS, health expectations, and expert Caddy snippets
- Public, internal, HTTP-only, and uploaded custom-certificate modes
- Automatic certificate renewal and HTTP-to-HTTPS redirects
- Configurable themed welcome, 404, redirect, no-response, and custom-HTML fallback pages
- Integrated, searchable documentation with real-world setup examples
- Administrator workspace for users, gateway defaults, security guidance, and backup/restore
- Downloadable, importable, scheduled, retained, and optionally encrypted `.sgbackup` archives
- Replace a site's files without recreating it
- Delete sites and their stored files
- Persistent configuration and uploads under `/data`
- Built-in transactional SQLite configuration database at `/data/database/site-gateway.sqlite`
- Unified certificate storage under `/data/certificates` and fixed backup storage under `/data/backups`
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

## Unraid alpha install

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

## ZimaOS alpha install

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
| `BACKUP_PASSWORD` | empty | Encryption password used only when encrypted scheduled backups are enabled |
| `PUID` | `1000` | UID that owns and runs against persistent files |
| `PGID` | `1000` | GID that owns and runs against persistent files |
| `ACME_EMAIL` | empty | Optional certificate account email |

At startup, the container creates the complete `/data` hierarchy, applies `PUID`/`PGID` ownership, and then drops root privileges. Configuration is stored in SQLite, hosted files remain in `/data/sites`, backups use `/data/backups`, uploaded certificates use `/data/certificates/custom`, and Caddy owns `/data/certificates/managed`. With the ZimaOS bind mount, these appear under `/DATA/AppData/site-gateway` on the host. Unraid commonly uses `PUID=99` and `PGID=100`; ZimaOS typically uses `1000:1000`.

## Backup and update

Open **Administration → Backup & restore** to create a Configuration or Complete backup. Manual backups download to the browser. Scheduled backups are stored under `/data/backups`, retained according to the interface setting, and can use AES-256-GCM encryption when `BACKUP_PASSWORD` is configured. A Complete backup contains a consistent SQLite snapshot, portable JSON recovery data, hosted files, local icons, custom fallback assets, and both custom and Caddy-managed certificate storage; logs are optional. Because certificate backups contain private keys, encryption is strongly recommended.

Before restoring, Site Gateway checks the archive manifest and creates a complete pre-restore safety backup. It then reloads persisted state and validates the resulting Caddy configuration. Store important backups on a separate disk or NAS share—copies in the same appdata volume do not protect against disk failure.

To rebuild after pulling a new version:

```bash
docker compose up -d --build
```

Your sites remain intact because they live in the mounted data directory.

## Publishing updates

The GitHub Actions workflow builds and publishes a fresh multi-architecture container whenever code is pushed to `main`. Alpha release tags publish an exact version and the moving `alpha` channel. For example, `v0.8.0-alpha.2` publishes `ghcr.io/mfwadejr/site-gateway:0.8.0-alpha.2` and `ghcr.io/mfwadejr/site-gateway:alpha`. The package starts private if the GitHub account's package defaults require it; make the `site-gateway` package public in GitHub package settings so Unraid and ZimaOS can pull without credentials.

### Monitoring in v0.5.0-alpha.1

- Certificate inventory shows issuer, expiration date, days remaining, provisioning state, and the last certificate-file update reported by Caddy.
- Dashboard alerts call out certificates within 30 days of expiration and unreachable proxy upstreams.
- Enabled proxy targets are checked every 60 seconds with a four-second timeout; status, HTTP response, latency, and recent in-memory history are available to the dashboard.
- Caddy access logs are stored as rotating JSON files under `/data/logs` and displayed without request headers. Gateway activity and errors are also appended to `/data/logs/activity.jsonl`.

`v0.5.0-alpha.2` clarifies that a missing stored certificate is **not detected**, rather than claiming issuance is actively provisioning, and includes a consistency pass for dashboard indicators, cards, and log controls.

### Users and roles in v0.6.0-alpha.1

- The environment-defined administrator becomes the initial persistent Administrator on first startup after upgrading.
- Administrators can create users, assign Administrator or Standard User roles, reset passwords, disable accounts, and archive or restore accounts.
- Standard Users have read-only access to dashboard health, hosted sites, proxy hosts, certificates, and logs. Per-host ownership and granular permissions are planned for a later release.
- Passwords are stored as salted scrypt hashes in the SQLite database; plaintext passwords are never written to disk.
- Site Gateway prevents removal of the final active Administrator and blocks users from disabling or archiving their own active session.

### Gateway management in v0.7.0-alpha.1

- Administration and Documentation appear directly above the installed-version divider; Administration is role-restricted.
- Proxy Hosts support multiple custom locations using `path | destination | strip-or-preserve`, request/response headers, upstream TLS controls, custom certificates, Access Lists, compression, and configurable health checks.
- Access List credentials are stored as salted password hashes and presented through a Site Gateway-themed login form. Network rules accept exact IP addresses, CIDR ranges, or Caddy's `private_ranges` token.
- Redirect Hosts and the configurable Default Site compile to native Caddy routes and are validated before reload.
- Expert Caddy snippets are administrator-only, size-limited, screened against global directives, and validated as part of the complete generated configuration.

### Storage foundation in v0.8.0-alpha.1

- SQLite is built into the container and stores configuration at `/data/database/site-gateway.sqlite`; no external database container or port is required.
- A seeded Local Gateway instance scopes every stored entity in preparation for future multi-instance management.
- Existing JSON installations are imported once into SQLite after a complete migration backup is written to `/data/backups`; original JSON snapshots remain under `/data/migrations`.
- Failed first-time imports remove the incomplete database so the migration safely retries after the source problem is corrected.
- Caddy-managed certificates and internal CA data live under `/data/certificates/managed`; uploaded certificates live under `/data/certificates/custom`; public exports are reserved under `/data/certificates/exports`.
- Backups contain a consistent SQLite snapshot, portable JSON recovery records, checksums, and optional complete filesystem content.

### First login in v0.8.0-alpha.2

- Fresh installations explain that the administrator credentials supplied to Docker are bootstrap credentials.
- After the first successful sign-in, the administrator must confirm or change the display name, username, and password before opening the dashboard.
- Completing setup rotates the account session identity and requires one final sign-in with the finalized credentials.
- Existing installations are treated as already configured and are not interrupted by the new workflow.

## Security notes

- Use unique bootstrap credentials during installation, then finalize the persistent administrator account during first-time setup.
- Keep the dashboard on a trusted LAN or behind a trusted HTTPS reverse proxy/VPN. The alpha dashboard itself serves plain HTTP.
- Do not expose the admin dashboard directly to the internet.
- Uploaded static JavaScript runs for visitors. Only publish files you trust.
- The container runs as the unprivileged `node` user and does not require access to the Docker socket.

## Troubleshooting

- **Site shows Error:** another process probably owns its port. Check `docker logs site-gateway`, then recreate the site on a free published port.
- **Site cannot be reached:** confirm the port is within the published Compose range and allowed through the server firewall.
- **Permission denied under `/data`:** make the host data directory writable by UID/GID 1000, or adjust ownership to match your environment.
- **Upload fails:** verify the file is below 250 MB and the extracted root contains `index.html`.
- **Dashboard port is busy:** change only the host side, such as `8180:8080`, then browse to port 8180.

## Alpha roadmap

Good next additions are per-site access logs, certificate status reporting, drag-and-drop folder upload, rollback/history, health checks, access lists, and guided DNS diagnostics.
