# Divebell fork development and release flow

This repository is a fork of
[`vercel-labs/agent-browser`](https://github.com/vercel-labs/agent-browser).
The `upstream` Git remote must point to that repository, while `origin` points
to the Divebell fork at [`2heal1/agent-browser`](https://github.com/2heal1/agent-browser).

## Branch relationship

```text
upstream/vX.Y.Z
    |
    | merge through codex/sync-upstream-vX.Y.Z
    v
codex/openruntime-agent-browser-release
    |
    | branch one feature at a time, then merge it back
    v
codex/<feature>
```

- `upstream/main` is the authoritative agent-browser development history. Sync
  a released version tag so the imported baseline is reproducible.
- `codex/openruntime-agent-browser-release` contains published Divebell package
  history and fork-only features. Never rebase or force-push this branch after
  a Divebell tag has been published.
- Sync upstream through a dedicated `codex/sync-upstream-vX.Y.Z` branch and a
  merge commit. This preserves both the upstream boundary and existing
  Divebell tag ancestry.
- Every new fork feature starts from the release branch on its own
  `codex/<feature>` branch. Merge it back only after review and verification.
- A generally useful change should also be proposed upstream. Keep the fork
  commit isolated until upstream accepts it; a later sync can then remove the
  duplicate fork implementation in a focused follow-up.

## Updating from upstream

```bash
git fetch upstream --tags
git fetch origin codex/openruntime-agent-browser-release
git switch -c codex/sync-upstream-v0.34.0 origin/codex/openruntime-agent-browser-release
git merge --no-ff v0.34.0
# Resolve conflicts, preserve the @divebell package identity, and run the full checks.
git push -u origin codex/sync-upstream-v0.34.0
```

Open a pull request from the sync branch into
`codex/openruntime-agent-browser-release`. Update the example tag and branch for
each upstream release; do not merge a moving `upstream/main` ref into the
release branch.

## Feature delivery

```bash
git switch codex/openruntime-agent-browser-release
git switch -c codex/<feature>
# implement and verify the feature
git push origin codex/<feature>
# review, then merge into codex/openruntime-agent-browser-release
```

Do not put unrelated product changes directly on the release branch. Keeping
each feature separate makes upstream rebases, reviews, and later removal of
fork-only patches predictable.

## Maintained fork change record

Changes listed here are carried by the Divebell release branch until they are available in an official agent-browser release.

- **Portable SSO state (`0.33.2-divebell.2`):** Auth state preserves CDP cookie priority, source, port, and partition metadata. `state save --include-origin <url>` is repeatable across the CLI and MCP so known authentication origins can contribute localStorage even when the active browser session did not navigate through them.
- **Side-effect-free state replay (`0.33.2-divebell.3`):** State loading restores localStorage and sessionStorage through intercepted blank responses so authentication origins are not contacted before the requested navigation and freshly loaded cookies cannot be invalidated by replay itself.
- **Install-script-free package (`0.33.2-divebell.3`):** The Divebell package relies on its bundled native binaries and the cross-platform wrapper's executable-bit repair, so it no longer declares an unnecessary `postinstall` lifecycle script that package-manager allowlists can block. Global npm symlinks and Windows shims therefore intentionally resolve through `bin/agent-browser.js`, which selects and launches the bundled native binary, rather than pointing directly to a platform binary.
- **Node 20 runtime package (`0.33.2-divebell.4`):** The npm package supports Node.js 20.19 or newer for installation and the JavaScript wrapper, while fork development and release tooling continue to use Node.js 24 and pnpm 11.
- **Restore State save stages (`0.33.2-divebell.5`):** Initial, periodic, and close-time saves are independently configurable on each command, including commands sent to an existing daemon. Cross-origin storage collection prefers a background CDP target and retains a compatibility fallback.
- **Compiled JavaScript debugger (`0.33.2-divebell.6`):** A lock-independent Chrome debugger control plane can inspect and resume paused JavaScript from a second CLI or MCP client. It provides compiled-source discovery and search, one-based UTF-16 breakpoint locations, conditional breakpoints, non-pausing logpoints, lifecycle events, and explicit `debug.inspect`, `debug.control`, and `evaluate` policy gates without requiring source files or source maps.
- **Navigation lifecycle timeouts (`0.33.2-divebell.7`):** `open`, `goto`, and `navigate` accept a per-command `--timeout`, default to a 60-second lifecycle wait, honor `AGENT_BROWSER_DEFAULT_TIMEOUT`, and carry the effective timeout into the IPC response budget. The MCP open tool exposes the same option as `timeoutMs`.
- **Active page context (`0.33.2-divebell.8`):** Partial launch envelopes inherit omitted options from the active browser configuration, so follow-up page commands reuse the page opened by the caller instead of relaunching Chrome at `about:blank`.

## Publishing the Divebell package

The published npm package is `@divebell/agent-browser`. Its version tracks the
upstream version and adds a Divebell prerelease suffix, for example
`0.34.0-divebell.1`.

1. Update the root package version and run `pnpm version:sync`.
2. Run the Rust tests and package checks locally.
3. Push the release branch.
4. Tag the exact release commit as `divebell-v<package-version>` and push the
   tag.
5. The `divebell-release.yml` workflow builds every supported binary, packs
   the npm artifact, validates its name and version, and publishes it through
   npm trusted publishing.
6. Install the exact published version in a clean temporary directory and run
   a real browser command before updating Divebell to consume it.
