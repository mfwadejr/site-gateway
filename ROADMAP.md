# Site Gateway product roadmap

## Current release status

`v0.12.0` marks a shift from the earlier per-fix `0.11.x` patch numbering to ordinary semantic versioning going forward — a minor bump for a real batch of changes, a patch bump for a targeted fix, rather than incrementing the same trailing number for every single change regardless of size. The product itself has moved well past the original alpha creation flow described in earlier versions of this document — Hosted Sites, Proxy Hosts, Redirect Hosts, and Streaming Hosts are all implemented, along with authentication, access control, certificates, backups, and full dashboard reporting. This document reflects what's actually shipped and what's genuinely still ahead.

`v0.13.0` is a real batch under that same convention, not a targeted fix, even though none of it changes what the app *does*: the in-app light theme has been removed entirely (the app is dark-only now, including the two visitor-facing themed pages -- the default-site 404/welcome/custom-HTML page and the Access-List sign-in page, both previously following the visitor's OS light/dark preference and now fixed dark for consistency with the rest of the app), the full color/spacing/radius design-token system begun in v0.12.0 has been completed (zero hardcoded color literals remain anywhere outside the token definitions), and `styles.css` has been restructured into commented, page-aligned sections matching the convention already used in `app.js`/`features.js`/`server.js`. A handful of small pre-existing bugs (a duplicate CSS custom property, some dead/duplicate rules, a decorative background glow that rendered incorrectly at certain aspect ratios) were also found and fixed along the way.

`v0.14.0` adds config-drift detection, a backup-encryption readiness check, and an app-wide dialog cleanup, and scopes out (but does not yet ship) a larger set of previously-discussed features tracked below as follow-up work.

- **Configuration drift detection** — a background check every 10 minutes compares Caddy's live running configuration (via its admin API `/config/` endpoint) against what Site Gateway's saved routes would currently generate (via `/adapt`). If they disagree \u2014 for example after a manual edit to the Caddyfile outside the app, or a Caddy restart that didn't pick up the latest reload \u2014 a "Configuration drift" item appears in the dashboard's Needs Attention list and a "Resync now" callout appears under Administration \u2192 Default site, both driven by a new `POST /api/gateway/resync` route that re-runs the normal Caddy sync and clears the flag.
- **Backup-encryption readiness** — the "Encrypt scheduled backups" checkbox no longer lets you configure something that will silently fail later. `/api/config` now reports whether the `BACKUP_PASSWORD` environment variable is actually set; the checkbox is disabled with an explanatory message when it isn't, and if it was previously saved as enabled and `BACKUP_PASSWORD` has since been removed, it shows a distinct warning instead of failing quietly at the next scheduled run.
- **Dialog cleanup** \u2014 every themed popout dialog's redundant "\u00d7" close button (in the dialog-heading row) has been removed app-wide; each dialog already has a working Cancel/Close button in its actions row, so this is pure de-duplication with no loss of function. New dialogs are expected to follow this pattern going forward.

### Follow-up work carried from this release's planning

A larger feature set was scoped for `v0.14.0` and intentionally deferred rather than shipped partially-verified. These remain on the roadmap for a future release:

- **REST API with issuable tokens** \u2014 admin-issued bearer tokens (full or read-only scope) for scripting against the Site Gateway API outside the browser session, bound to the issuing user's session version so a password reset/deactivation revokes them automatically.
- **Backup/restore history** \u2014 a durable, database-backed history of every backup, restore, and deletion (including failed attempts), shown as a human-readable timeline that never displays raw backup filenames.
- **Docker container picker** \u2014 an opt-in integration (gated on the Docker socket being mounted and readable) that lets Proxy/Streaming targets be picked from the host's running containers instead of typed by hand, using each container's Docker DNS name.
- **"View Caddy config" popout** \u2014 a read-only, prettified view of the exact Caddy configuration block generated for a given site, proxy, or redirect, built from the same code path that generates the real deployed config so it can never drift from it.
- **Performance screen overhaul** \u2014 clock-aligned time-axis labels, a y-axis unit, hover tooltips with error counts, p95 latency, bandwidth and unique-visitor columns, a 4xx/5xx-colored error breakdown, top-paths-per-host, and a slowest-requests panel.
- **Dashboard tile color unification** \u2014 normalizing all "normal count" tiles to a shared green baseline that reacts to warning/danger states the same way the existing Needs Attention tile does.

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

### Certificates and TLS

- Automatic public HTTPS via Caddy, plus internal, HTTP-only, and uploaded custom-certificate modes.
- Certificate inventory: issuer, covered domains, validity, serial number, fingerprint, expiration, and last detected update.
- Dashboard alerts for certificates nearing expiration.

### Observability

- Live dashboard health for the gateway, HTTP, HTTPS, and storage, plus hosted/proxy/certificate counts and throughput.
- System panel: uptime, memory, persistent-data size, disk space, installed app/Caddy versions, public IP.
- Performance view with request throughput, response times, and per-route breakdowns — the host filter applies to the throughput table as well as the trend chart, average response times display in seconds once they pass 1000ms, and per-domain error counts open a themed breakdown by status code.
- Rotating access and activity logs.
- Update-available banner when a newer image is deployed.
- A redacted support-report export exists (version, config health, certificate readiness, upstream checks, recent events) but its UI entry point is currently hidden pending a readability rewrite of the report's output format.

### Data and operations

- Built-in SQLite persistence at `/data/database/site-gateway.sqlite` — no external database container.
- Configuration and Complete backups, downloadable, importable, schedulable, and optionally AES-256-GCM encrypted; pre-restore safety backups and configuration validation before activation.
- PUID/PGID-aware startup for Unraid and ZimaOS-style permission models.

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
- **Browsable backup/restore history** — today a restore validates and rolls back safely, but there's no UI history of past backups beyond what's on disk.
- **Container picker for Proxy/Streaming targets** — letting a target be selected from a list of running Docker containers instead of typed as an IP/hostname, gated behind an opt-in Docker-socket mount since it needs real access to the Engine API. Also needs a shared Docker network between Site Gateway and the target container to actually be reachable, not just discoverable.
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
