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

### Phase 1 — Domains and automatic HTTPS (gateway beta implemented)

- Publish ports 80 and 443
- Domain assignment for static sites
- Automatic certificate issue and renewal
- Force-HTTPS option
- Certificate status and expiration reporting
- Guided DNS/router readiness checks

### Phase 2 — Reverse proxy and redirects (proxy hosts implemented; redirects/logs pending)

- Proxy to other containers, LAN devices, or URLs
- WebSocket support
- Redirect hosts and offline/404 hosts
- Standard security-header presets
- Optional HSTS after HTTPS is verified
- Per-host access logs and simple health checks

### Phase 3 — Access and advanced certificates

- Basic-auth access policies reusable across sites
- IP allow/deny lists
- Custom certificate upload
- Wildcard certificates through selected DNS providers
- Backup/export and restore
- Configuration history and one-click rollback

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

Build Phases 1 and 2 first. They provide the high-value Nginx Proxy Manager experience—domains, HTTPS, proxy hosts, redirects, access controls, and clear status—without inheriting the complexity of full user management, raw server configuration, and stream proxying on day one.
