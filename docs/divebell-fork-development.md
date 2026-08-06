# Divebell fork development and release flow

This repository is a fork of
[`vercel-labs/agent-browser`](https://github.com/vercel-labs/agent-browser).
The `upstream` Git remote must point to that repository, while `origin` points
to the Divebell fork at [`2heal1/agent-browser`](https://github.com/2heal1/agent-browser).

## Branch relationship

```text
upstream/main
    |
    | rebase
    v
feat/memory-diagnostics
    |
    | base for the Divebell package changes
    v
codex/openruntime-agent-browser-release
    |
    | branch one feature at a time, then merge it back
    v
codex/<feature>
```

- `upstream/main` is the authoritative agent-browser history.
- `feat/memory-diagnostics` contains only the reusable memory and coverage
  diagnostics. Rebase it directly onto `upstream/main`.
- `codex/openruntime-agent-browser-release` contains the diagnostics plus the
  Divebell package identity and release workflow. Rebase its release-only
  commits onto the updated diagnostics branch.
- Every new fork feature starts from the release branch on its own
  `codex/<feature>` branch. Merge it back only after review and verification.
- A generally useful change should also be proposed upstream. Keep the fork
  commit isolated until upstream accepts it; the next rebase can then drop the
  duplicate fork commit.

## Updating from upstream

```bash
git fetch upstream --tags
git switch feat/memory-diagnostics
git rebase upstream/main
git push --force-with-lease origin feat/memory-diagnostics

git switch codex/openruntime-agent-browser-release
git rebase --onto feat/memory-diagnostics <old-memory-commit> codex/openruntime-agent-browser-release
git push --force-with-lease origin codex/openruntime-agent-browser-release
```

Replace `<old-memory-commit>` with the former memory-diagnostics commit at the
base of the release branch. Confirm with `git log --graph` that the release
branch contains one memory-diagnostics commit followed by its release-only
commits.

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
- **Install-script-free package (`0.33.2-divebell.3`):** The Divebell package relies on its bundled native binaries and the cross-platform wrapper's executable-bit repair, so it no longer declares an unnecessary `postinstall` lifecycle script that package-manager allowlists can block.
- **Node 20 runtime package:** The npm package supports Node.js 20.19 or newer for installation and the JavaScript wrapper, while fork development and release tooling continue to use Node.js 24 and pnpm 11.

## Publishing the Divebell package

The published npm package is `@divebell/agent-browser`. Its version tracks the
upstream version and adds a Divebell prerelease suffix, for example
`0.33.2-divebell.1`.

1. Update the root package version and run `npm run version:sync`.
2. Run the Rust tests and package checks locally.
3. Push the release branch.
4. Tag the exact release commit as `divebell-v<package-version>` and push the
   tag.
5. The `divebell-release.yml` workflow builds every supported binary, packs
   the npm artifact, validates its name and version, and publishes it through
   npm trusted publishing.
6. Install the exact published version in a clean temporary directory and run
   a real browser command before updating Divebell to consume it.
