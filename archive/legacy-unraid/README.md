# Legacy Unraid Community Apps template (archived, unfinished)

This is the Unraid Community Apps template (`site-gateway.xml`) as it existed in the original `mfwadejr/site-gateway` repo before that repo was retired. It is **not currently submittable as-is**:

- It points at the old image tag `ghcr.io/mfwadejr/site-gateway:0.11.28` and the old repo's `Support`/`Project`/`Icon` URLs — all of which need updating to reflect `site-gateway2`.
- It was never finalized or submitted to the actual Unraid Community Apps store, and likely does not fully conform to that store's current submission requirements (see the open "Unraid Community Apps submission" backlog item in the project's build backlog for what's still missing: `ca_profile.xml`, correct `<Repository>`, etc.).

Kept here for historical reference and as a real head start if/when that backlog item is picked up — most of the port/volume/env-var scaffolding below is still structurally correct for site-gateway2, it just needs the identifying URLs and image reference updated.
