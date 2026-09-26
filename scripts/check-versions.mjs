#!/usr/bin/env node
// Verifies that package.json's version, the README version badge, ROADMAP.md's
// "current release" pointer, and CHANGELOG.md's newest entry all agree.
//
// Run locally with `npm run check:versions` before shipping any release, and
// it also runs in CI (see .github/workflows/container.yml) so a mismatch
// fails the build loudly instead of drifting silently.
//
// Convention this depends on: CHANGELOG.md entries are appended to the END
// of the file (oldest first, truly), so the LAST "## vX.Y.Z" heading is
// always the newest release. Never prepend a new entry after the intro --
// append it after the last existing entry instead.

import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");

function read(path) {
  return readFileSync(join(root, path), "utf8");
}

const errors = [];

const pkg = JSON.parse(read("package.json"));
const pkgVersion = pkg.version;
if (!pkgVersion) errors.push("package.json has no \"version\" field.");

const readme = read("README.md");
const badgeMatch = readme.match(/version-([\d.]+)-62E6A7/);
if (!badgeMatch) {
  errors.push("README.md: could not find the version badge (version-X.Y.Z-62E6A7).");
} else if (badgeMatch[1] !== pkgVersion) {
  errors.push(`README.md badge says ${badgeMatch[1]}, package.json says ${pkgVersion}.`);
}

const roadmap = read("ROADMAP.md");
const currentMatch = roadmap.match(/`v([\d.]+)`\s+is current\./);
if (!currentMatch) {
  errors.push("ROADMAP.md: could not find the \"`vX.Y.Z` is current.\" sentence in Current release status.");
} else if (currentMatch[1] !== pkgVersion) {
  errors.push(`ROADMAP.md says v${currentMatch[1]} is current, package.json says ${pkgVersion}.`);
}

const changelog = read("CHANGELOG.md");
const headingMatches = [...changelog.matchAll(/^## v([\d.]+)\s*$/gm)];
if (headingMatches.length === 0) {
  errors.push("CHANGELOG.md: no \"## vX.Y.Z\" headings found.");
} else {
  const lastHeadingVersion = headingMatches[headingMatches.length - 1][1];
  if (lastHeadingVersion !== pkgVersion) {
    errors.push(
      `CHANGELOG.md's last entry is v${lastHeadingVersion}, package.json says ${pkgVersion}. ` +
      `Add a "## v${pkgVersion}" entry at the END of CHANGELOG.md (append, don't prepend).`
    );
  }
}

if (errors.length) {
  console.error("Version sync check failed:\n");
  for (const e of errors) console.error(`  - ${e}`);
  console.error("\nREADME.md, ROADMAP.md, and CHANGELOG.md must all reference the current package.json version before shipping.");
  process.exit(1);
}

console.log(`Version sync OK: README.md, ROADMAP.md, and CHANGELOG.md all agree on v${pkgVersion}.`);
