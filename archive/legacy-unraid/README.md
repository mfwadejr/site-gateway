# Legacy Unraid Community Apps template (superseded, removed 2026-09-27)

This folder used to hold `site-gateway.xml`, the Unraid Community Apps template as it existed in the original `mfwadejr/site-gateway` repo before that repo was retired. It pointed at the old image tag `ghcr.io/mfwadejr/site-gateway:0.11.28` and the old repo's `Support`/`Project`/`Icon` URLs, and was never finalized or submitted.

**The file has been deleted.** Unraid's submission scanner walks the whole repository for any file with a `<Container>` root element, not just a `templates/` folder — so leaving this stale template archived here (rather than actually removed) caused a real submission failure: the scanner picked it up instead of the real template, surfacing the wrong (0.11.28) version and a broken icon reference.

The real, finalized, submittable template now lives at `templates/site-gateway.xml`, alongside `icon.svg` and `ca_profile.xml` at the repo root. See the project's build backlog for the full history of decisions behind that template.
