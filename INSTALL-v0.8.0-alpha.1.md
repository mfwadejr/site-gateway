# Site Gateway v0.8.0-alpha.1 installation

This release contains Caddy and SQLite inside one container. It needs no external database and uses one persistent `/data` mount. Backups are stored in `/data/backups`.

## ZimaOS Compose YAML

Replace the two secrets before importing this YAML as a custom application.

```yaml
name: site-gateway

services:
  site-gateway:
    image: ghcr.io/mfwadejr/site-gateway:0.8.0-alpha.1
    container_name: site-gateway
    restart: unless-stopped
    environment:
      ADMIN_USERNAME: admin
      ADMIN_PASSWORD: REPLACE_WITH_A_LONG_UNIQUE_PASSWORD
      SESSION_SECRET: REPLACE_WITH_AT_LEAST_32_RANDOM_CHARACTERS
      ADMIN_PORT: "8080"
      SITE_PORT_MIN: "9000"
      SITE_PORT_MAX: "9099"
      DATA_DIR: /data
      BACKUP_PASSWORD: ""
      PUID: "1000"
      PGID: "1000"
      ACME_EMAIL: ""
    ports:
      - "80:80/tcp"
      - "443:443/tcp"
      - "443:443/udp"
      - "8080:8080/tcp"
      - "9000-9099:9000-9099/tcp"
    volumes:
      - /DATA/AppData/site-gateway:/data
```

Open `http://ZIMAOS-IP:8080` after the container starts.

## Docker CLI

```bash
docker pull ghcr.io/mfwadejr/site-gateway:0.8.0-alpha.1

docker run -d \
  --name site-gateway \
  --restart unless-stopped \
  -p 80:80/tcp \
  -p 443:443/tcp \
  -p 443:443/udp \
  -p 8080:8080/tcp \
  -p 9000-9099:9000-9099/tcp \
  -v /DATA/AppData/site-gateway:/data \
  -e ADMIN_USERNAME=admin \
  -e ADMIN_PASSWORD='REPLACE_WITH_A_LONG_UNIQUE_PASSWORD' \
  -e SESSION_SECRET='REPLACE_WITH_AT_LEAST_32_RANDOM_CHARACTERS' \
  -e ADMIN_PORT=8080 \
  -e SITE_PORT_MIN=9000 \
  -e SITE_PORT_MAX=9099 \
  -e DATA_DIR=/data \
  -e BACKUP_PASSWORD='' \
  -e PUID=1000 \
  -e PGID=1000 \
  -e ACME_EMAIL='' \
  ghcr.io/mfwadejr/site-gateway:0.8.0-alpha.1
```

Generate a session secret on a computer with OpenSSL:

```bash
openssl rand -hex 32
```

## Persistent layout

```text
/DATA/AppData/site-gateway/
├── backups/
├── caddy/
├── certificates/
│   ├── custom/
│   ├── exports/
│   └── managed/
├── database/
│   └── site-gateway.sqlite
├── default-site/
├── icons/
├── logs/
├── migrations/
└── sites/
```

Do not manually edit SQLite, Caddy-managed certificate files, or private keys while the container is running.

## Port conflicts

Ports 80 and 443 must be free for public automatic HTTPS. Stop any existing reverse proxy before assigning those host ports to Site Gateway. For temporary dashboard testing, change only the host side of the dashboard mapping, such as `8180:8080`.

## Updates and rollback

Create a Complete backup from **Administration → Backup & restore** before updating. Always pin an exact alpha image. To roll back, recreate the container with the earlier image and restore the backup produced by that earlier release.
