# Site Gateway product roadmap

## Product direction

Site Gateway should remain simpler than a general-purpose proxy manager: one dashboard, clear health reporting, and guided setup instead of exposing server configuration. It can still cover most home-server publishing needs with an HTTP/HTTPS gateway alongside the existing static-file service.

## Recommended gateway

Use **Caddy** as the managed gateway rather than rebuilding certificate and proxy behavior in Node or exposing raw Nginx configuration. The dashboard would store a small site model and generate/apply gateway configuration. Caddy provides automatic certificate issuance and renewal, redirects HTTP to HTTPS, supports reverse proxying and WebSockets, and has a configuration API suitable for safe validation before activation.

The existing Node application remains responsible for authentication, the wizard, uploads, persistence, status, and audit events. Static sites can continue to use internal listeners while Caddy becomes the only public entry point on ports 80 and 443.

## Proposed creation wizard

### Step 1: What are you publishing?

- Static website — upload a ZIP or `index.html`
- Existing application — proxy to an IP/hostname and port
- Redirect — send a domain or path to another URL
- Offline page — intentionally return a friendly maintenance/404 response

### Step 2: Address

- Domain name(s)
- Optional path such as `/photos`
- Internal target and port for proxied applications
- Validation that ports and domains are not duplicated

### Step 3: Security

- Automatic public TLS certificate
- HTTP only for trusted LAN use
- Upload an existing certificate
- Force HTTPS
- HSTS, shown as an advanced option with a clear lockout warning

### Step 4: Access

- Public
- Basic username/password
- IP allow/deny list
- Optional security headers preset

### Step 5: Review and publish

- Plain-language configuration summary
- DNS and router checks
- Configuration validation before activation
- Immediate rollback if gateway reload fails

## Delivery phases

### Dashboard foundation (implemented in v0.4.0-alpha.1)

- Default overview with hosted-site, proxy-host, TLS-domain, and attention totals
- Gateway, hosted-site, and proxy-host health indicators
- Safe runtime reporting for uptime, memory, persistent-data size, disk space, and installed versions
- Recent configuration activity for the current container session
- Responsive navigation for desktop and mobile
- Infrastructure-focused live health for Caddy, HTTP, HTTPS automation, and persistent storage (refined in v0.4.0-alpha.2)
- Confirmed port health, clearer storage reporting, local service icons, and resilient dashboard controls (v0.4.0-alpha.3)
- Certificate inventory and expiration alerts, proxy upstream monitoring, and filtered rotating access logs (v0.5.0-alpha.1)
- Corrected certificate wording and standardized dashboard, card, and log-control spacing (v0.5.0-alpha.2)
- Persistent local users, Administrator and Standard User roles, account lifecycle controls, and role-aware sessions (v0.6.0-alpha.1)
- Redirect Hosts, Access Lists with themed authentication, advanced Proxy Host controls, custom certificates, configurable fallback pages, integrated documentation, Administration, and backup/restore (v0.7.0-alpha.1)
- Built-in SQLite persistence, Local Gateway instance scoping, JSON migration safeguards, unified certificate storage, and database-aware backups (v0.8.0-alpha.1)
- First-install sign-in guidance and required one-time administrator account finalization (v0.8.0-alpha.2)

### Next alpha milestone — visibility and certificate health

This should be the next implementation target. It adds the reporting people rely on in NGINX Proxy Manager without expanding the creation workflow yet.

- Certificate inventory derived from Caddy's managed certificate storage
- Domain, issuer, valid-from, expiration date, and days remaining
- Clear **Healthy**, **Renewing soon**, **Expired**, and **Needs attention** states
- Dashboard counts for certificates expiring within 30 and 7 days
- Last successful renewal and last certificate error when available
- Per-host upstream reachability checks with response time and last-check timestamp
- Recent gateway errors and a concise per-host access-log view
- Diagnostics that distinguish DNS, inbound port, certificate, and upstream failures
- Never display private keys, account credentials, or raw sensitive configuration

### Phase 1 — Domains and automatic HTTPS (gateway alpha implemented)

- Publish ports 80 and 443
- Domain assignment for static sites
- Automatic certificate issue and renewal
- Force-HTTPS option
- Certificate status and expiration reporting (next alpha milestone)
- Guided DNS/router readiness checks (next alpha milestone)

### Phase 2 — Reverse proxy and redirects (implemented)

- Proxy to other containers, LAN devices, or URLs
- WebSocket support
- Redirect hosts and offline/404 hosts
- Standard security-header presets
- Optional HSTS after HTTPS is verified
- Per-host access logs and simple health checks

### Phase 3 — Access and advanced certificates (partially implemented)

- Themed-login access policies reusable across proxy hosts (implemented)
- IP/CIDR allow lists (implemented)
- Custom certificate upload (implemented)
- Wildcard certificates through selected DNS providers
- Backup/export and restore, including encryption and scheduling (implemented)
- Configuration validation and automatic restore rollback (implemented); browsable history remains planned

### Phase 4 — Multi-user and specialist features

- Multiple administrators and roles
- Audit log
- TCP/UDP stream forwarding
- Rate limiting
- Carefully constrained advanced configuration snippets

## Important constraints

- Public automatic certificates require working public DNS and inbound access to ports 80/443 unless a DNS challenge is configured.
- HSTS should never be enabled by default; a bad configuration can make a domain inaccessible until the browser policy expires.
- Wildcard/DNS certificates require storing DNS-provider credentials and therefore need encrypted secret storage.
- Ports 80 and 443 must not already be owned by another reverse proxy on the same host.
- Arbitrary Nginx/Caddy snippets substantially increase support and security risk and should remain an expert-only feature.

## Scope recommendation

Prioritize reporting before adding more creation options: certificate health, renewal visibility, upstream checks, and useful logs make the existing gateway trustworthy. Follow that with redirect hosts and reusable access lists. Custom certificates, DNS challenges, streams, multi-user roles, and raw snippets should remain later advanced work because they add credential-storage, validation, and support complexity.

## NGINX Proxy Manager alignment

| Capability | Site Gateway direction | Priority |
| --- | --- | --- |
| Proxy hosts, WebSockets, automatic HTTPS | Implemented through guided Caddy configuration | Current |
| Certificate expiration and renewal reporting | First-class certificate health page and dashboard alerts | Next |
| Access logs and traffic reporting | Recent requests, status distribution, bytes, and errors per host; avoid promising full analytics | Next |
| Upstream health | Reachability, response time, and failure reason per proxy target | Next |
| Redirect hosts and maintenance responses | Implemented as Redirect Hosts and configurable Default Site behaviors | Current |
| Access lists and authentication | Reusable policies with network rules and a themed sign-in flow | Current |
| DNS and reachability diagnostics | Guided checks for resolution, public IP, ports 80/443, and certificate eligibility | Near term |
| Custom certificates | Validated matching certificate/key upload and complete-backup support | Current |
| Wildcard certificates | Selected DNS-provider integrations with encrypted API credentials | Later |
| Advanced proxy options | Custom locations, headers, compression, upstream TLS, health expectations, and validated snippets | Current |
| TCP/UDP streams | Separate advanced area with explicit port-conflict checks | Later |
| Backup and restore | Configuration/complete archives, browser download/import, schedules, retention, encryption, and rollback | Current |
