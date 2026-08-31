# Web Server

Web Server is a small, self-hosted Docker appliance for publishing static websites without editing proxy or server configuration. Create a site, upload a ZIP, choose a port, and it is immediately available.

## Beta features

- Password-protected, responsive admin dashboard
- Create a site from a ZIP archive or a single `index.html`
- One independently enabled/disabled port per site
- Replace a site's files without recreating it
- Delete sites and their stored files
- Persistent configuration and uploads under `/data`
- Path traversal protection for ZIP extraction and a 250 MB upload limit
- Clean shutdown and automatic site restart after a container restart

This first beta serves **static sites only** (HTML, CSS, JavaScript, images, fonts, and downloads). It does not run PHP, Node, Python, databases, TLS certificates, domains, or reverse proxy rules.

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

## Install from the published image

Each push to `main` automatically publishes `ghcr.io/mfwadejr/web-server:latest` for both Intel/AMD and ARM64 servers. Copy `.env.example` to `.env`, replace the password and session secret, then run:

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

A ZIP containing one top-level folder is also accepted; Web Server unwraps that folder automatically.

## Unraid beta install

### Option A: Compose Manager

1. Install **Compose Manager** from Community Applications if it is not already present.
2. Copy this project folder to `/mnt/user/appdata/web-server/app`.
3. In `compose.yaml`, change the volume to `/mnt/user/appdata/web-server/data:/data`.
4. Set a strong `ADMIN_PASSWORD`. Optionally set a long random `SESSION_SECRET`.
5. Add the stack in Compose Manager and choose **Compose Up**.
6. Open `http://UNRAID-IP:8080`.

For automatic image-based upgrades, use `compose.release.yaml` instead. Unraid's **Update Container** action can pull the newest `latest` image. If you already use Watchtower, the release Compose file includes its opt-in label.

### Option B: build from the Unraid terminal

```bash
cd /mnt/user/appdata/web-server/app
docker compose up -d --build
```

If Unraid reports a port conflict, change the admin port mapping's left side (for example `8180:8080`) or choose a different site-port range. Allow the selected site ports through any LAN firewall.

## ZimaOS beta install

1. Copy this folder into ZimaOS storage, for example `/DATA/AppData/web-server/app`.
2. Change the Compose volume to `/DATA/AppData/web-server/data:/data`.
3. Set a strong `ADMIN_PASSWORD` and optionally `SESSION_SECRET`.
4. In the ZimaOS app interface, use its custom app / Compose import option and paste or select `compose.yaml`. If that option is unavailable in your release, use the terminal:

   ```bash
   cd /DATA/AppData/web-server/app
   docker compose up -d --build
   ```

5. Open `http://ZIMAOS-IP:8080`.

For simple upgrades, import `compose.release.yaml`; use ZimaOS's container update/recreate action whenever a new image is published. The `/data` mount keeps all sites during replacement.

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

## Backup and update

Back up the entire mounted `data` directory. It contains `sites.json` and every uploaded site.

To rebuild after pulling a new version:

```bash
docker compose up -d --build
```

Your sites remain intact because they live in the mounted data directory.

## Publishing updates

The GitHub Actions workflow builds and publishes a fresh multi-architecture container whenever code is pushed to `main`. A tag such as `v0.2.0` also produces a matching versioned image. The package starts private if the GitHub account's package defaults require it; make the `web-server` package public in GitHub package settings so Unraid and ZimaOS can pull without credentials.

## Security notes

- Change the default password before first use.
- Keep the dashboard on a trusted LAN or behind a trusted HTTPS reverse proxy/VPN. The beta dashboard itself serves plain HTTP.
- Do not expose the admin dashboard directly to the internet.
- Uploaded static JavaScript runs for visitors. Only publish files you trust.
- The container runs as the unprivileged `node` user and does not require access to the Docker socket.

## Troubleshooting

- **Site shows Error:** another process probably owns its port. Check `docker logs web-server`, then recreate the site on a free published port.
- **Site cannot be reached:** confirm the port is within the published Compose range and allowed through the server firewall.
- **Permission denied under `/data`:** make the host data directory writable by UID/GID 1000, or adjust ownership to match your environment.
- **Upload fails:** verify the file is below 250 MB and the extracted root contains `index.html`.
- **Dashboard port is busy:** change only the host side, such as `8180:8080`, then browse to port 8180.

## Beta roadmap

Good next additions are custom domains and HTTPS integration, per-site access logs, drag-and-drop folder upload, rollback/history, health checks, and optional reverse-proxy templates.
