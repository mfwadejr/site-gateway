# Alpha 96 validation checklist

Alpha 96 hardening is being delivered in stages. Backup and restore validation is intentionally reserved for the final Alpha 96 patch.

## Covered before backup validation

- Viewer, Standard User, and Administrator permission regression checks.
- Multi-domain and Access List persistence checks.
- SQLite startup integrity and existing-data migration checks.
- Fresh-install setup and upgrade checks.
- Caddy configuration validation before reload.

## Final Alpha 96 step

- Configuration and complete backup creation, download, restore, and rollback validation.
- Verification that audit events, users, groups, routes, domains, and icons survive restore.
