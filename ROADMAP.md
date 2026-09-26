# Site Gateway product roadmap

## Current release status

`v0.16.105` is current. Site Gateway is a single container that gives a homelab or small team one dashboard for Hosted Sites, Proxy Hosts, Redirect Hosts, and Streaming Hosts, with Caddy handling routing and automatic HTTPS underneath. Authentication, roles (Administrator/Standard/Viewer), Groups, Access Lists, two-factor authentication, a REST API with issuable tokens, encrypted backups with scheduled runs and full restore history, a combined Logs page (access requests, gateway events, and an administrator-only audit log, all under one unified event categorization), configuration-drift detection, and a three-source icon mirror (dashboard-icons, selfh.st, and Lucide) are all implemented and shipped, not planned.

Versioning has followed ordinary semantic versioning since `v0.12.0`: a minor bump for a real batch of changes, a patch bump for a targeted fix, rather than incrementing the same trailing number for every change regardless of size. Everything below this line is the full version history, oldest conventions first.

## Product direction

Site Gateway stays simpler than a general-purpose proxy manager: one dashboard, clear health reporting, and guided setup instead of exposing raw server configuration. **Caddy** remains the managed gateway — Site Gateway stores a small route model and generates/validates Caddy configuration rather than reimplementing certificate and proxy behavior itself.

## Shipped

### Routing

- **Hosted Sites** — upload a ZIP or `index.html`, publish on a domain and/or a direct LAN port, replace files without recreating the site.
- **Proxy Hosts** — forward a domain to any HTTP(S) target, with custom locations, headers, compression, upstream TLS, health checks, load-balancing across multiple upstreams, and expert Caddy snippets.
- **Redirect Hosts** — 301/302/307/308 responses with optional path preservation.
- **Streaming Hosts** — native TCP/UDP port forwarding with monitoring, for services that aren't HTTP (game servers, SSH, etc).
- Configurable themed welcome, 404, redirect, no-response, and custom-HTML fallback pages, with a live preview pane in Gateway Defaults.

### Access and identity

- Local users with Administrator and Standard User roles, account lifecycle controls (disable/archive/restore).
- Groups, used to grant Access List membership without managing users one by one.
- Access Lists combining accounts, groups, and IP/CIDR network rules behind a themed sign-in page.
- Optional two-factor authentication (TOTP) with a self-service My Account view for enrolling and managing it, plus an administrator-side override (Administration → Users → “•••” → Disable 2FA) for a user who's locked out with no recovery codes left. Logged to the Audit log.
- First-time setup flow that finalizes the persistent administrator account from bootstrap credentials.
- REST API with admin-issued bearer tokens (full or read-only scope), bound to the issuing user’s session version so a password reset or deactivation revokes them automatically.

### Certificates and TLS

- Automatic public HTTPS via Caddy, plus internal, HTTP-only, and uploaded custom-certificate modes.
- Certificate inventory: issuer, covered domains, validity, serial number, fingerprint, expiration, and last detected update.
- Dashboard alerts for certificates nearing expiration.

### Observability

- Live dashboard health for the gateway, HTTP, HTTPS, and storage, plus hosted/proxy/certificate counts and throughput.
- System panel: uptime, memory, persistent-data size, disk space, installed app/Caddy versions, public IP.
- Performance view with request throughput, response times, per-route breakdowns, p95 latency, bandwidth, and unique-visitor columns, a 4xx/5xx-colored error breakdown, a top-10-paths-per-host popout, and a slowest-requests panel — the host filter applies to the throughput table as well as the trend chart, and average response times display in seconds once they pass 1000ms.
- A read-only "View Caddy config" popout on Hosted Sites, Proxy Hosts, and Redirect Hosts, showing the exact Caddyfile block generated for that route, built from the same code path that generates the real deployed config so it can never drift from what’s shown.
- Dashboard tile colors are unified around a shared green baseline that reacts to warning/danger states, matching the existing Needs Attention tile’s behavior.
- Configuration drift detection compares Caddy’s live configuration against the saved routes every 10 minutes, flags a Needs Attention item with a one-click inline "Resync now" action, and logs a Gateway Events entry the first time drift is detected.
- Rotating access and activity logs.
- Update-available banner when a newer image is deployed.
- A redacted support-report export exists (version, config health, certificate readiness, upstream checks, recent events) but its UI entry point is currently hidden pending a readability rewrite of the report's output format.

### Data and operations

- Built-in SQLite persistence at `/data/database/site-gateway.sqlite` — no external database container.
- Configuration and Complete backups, downloadable, importable, schedulable, and optionally AES-256-GCM encrypted; pre-restore safety backups and configuration validation before activation.
- PUID/PGID-aware startup for Unraid and ZimaOS-style permission models.
- A durable, database-backed history of every backup, restore, and deletion attempt, shown as a human-readable timeline.
- An opt-in Docker container picker (gated on the Docker socket being mounted and readable) for choosing Proxy/Streaming targets from the host’s running containers instead of typing them by hand.

- A System tab (Administration) surfacing environment/integration status, security status, storage usage, scheduled jobs, gateway sync status, and reload/restart controls in one read-only operations page.

### Brand and docs

- Current icon and wordmark (v0.11.99) used consistently across the login screen, sidebar, themed default pages, and this README.
- A sitewide design-token system (colors, spacing, radius, and type scale defined once and reused everywhere) underpins the interface, so new UI stays visually consistent by default.
- Integrated, searchable in-app documentation covering every configurable field, including 2FA (self-service and the administrator override) and the update-notification banner.
- Toast notifications are color-coded — error toasts render distinctly from success/neutral ones, using the same token-driven theming as the rest of the interface.
- Companion marketing site with an installation guide covering Docker Compose, plain `docker run`, and Unraid.

## What's next

Roughly in priority order:

- **Richer certificate diagnostics** — on-demand checks that distinguish DNS, inbound port, TLS, and upstream failures per domain.
- **Wildcard/DNS-challenge certificates** — selected DNS-provider integrations for domains that can't use HTTP-01 validation. Needs encrypted secret storage for provider API credentials before it ships.
- **Tailscale integration** — documented patterns exist today (host-level Tailscale for private dashboard access, a sidecar container for proxying to tailnet-only targets, `tailscale serve`/`funnel` for exposing a route without opening router ports), but nothing is built into Site Gateway itself yet.
- **Dynamic DNS** and **deeper Caddy controls** for advanced users who outgrow the guided options.
- **Rate limiting** and other specialist gateway controls.

## Important constraints

- Public automatic certificates require working public DNS and inbound access to ports 80/443 unless a DNS challenge is configured.
- HSTS should never be enabled by default; a bad configuration can make a domain inaccessible until the browser policy expires.
- Wildcard/DNS certificates require storing DNS-provider credentials and therefore need encrypted secret storage before they can ship.
- Ports 80 and 443 must not already be owned by another reverse proxy on the same host.
- A Docker-socket-based container picker is opt-in only — socket access is root-equivalent on the host and should never be a default requirement.
- Arbitrary Caddy snippets substantially increase support and security risk and stay an expert-only, size-limited, validated feature.

Full per-release history lives in [CHANGELOG.md](CHANGELOG.md).
