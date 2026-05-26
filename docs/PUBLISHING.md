# Publishing Checklist

This package is npm-publishable from a packaging standpoint. It still uses a
private Oneleet web surface, not an official public Oneleet API, so publication
should remain a deliberate Daniel decision.

## Release Gate

Run this before sharing the source tree or a tarball:

```bash
npm run check:release
```

That runs:

- TypeScript typecheck.
- Synthetic fixture tests only.
- Public package surface audit through `npm pack --dry-run`.

The release gate includes the repo-local secret sweep. You can also run it
directly:

```bash
npm run secret-sweep
```

The package also includes GitHub Actions workflows:

- `.github/workflows/ci.yml` runs gitleaks, tracked-capture checks, and the
  release gate on Node 22 and 24 for pull requests, pushes to `main`, and
  manual dispatch.
- `.github/workflows/publish.yml` is manual-only. It defaults to
  `npm publish --dry-run` and requires setting `dry_run=false` before publishing.
  Configure `NPM_TOKEN` or npm trusted publishing before using the real publish
  step.

The package name `oneleet-cli` was checked against npm on 2026-05-21 and was not
registered at that time. Re-check immediately before the first publish.

## Must Stay Out Of Source

- live `oneleet-app` cookies
- `~/.config/oneleet/config.json`
- non-synthetic uses of `ONELEET_ALLOW_UNSAFE_API_BASE_URL=1`
- HARs, browser traces, storage state, screenshots, or raw network captures
- raw Oneleet JSON exports from live tenants
- generated reports with tenant names, emails, URLs, file names, UUIDs, or local paths

## Package Contents

Expected npm tarball contents:

- `dist/`
- `docs/`
- `skills/`
- `README.md`
- `CONTRIBUTING.md`
- `SECURITY.md`
- `SKILL.md`
- `LICENSE`
- `package.json`

Tests, scripts, `src/`, `node_modules/`, local reports, browser captures, and auth material must not be included in the tarball.

## Runtime Output Rules

Use aggregate commands for reports:

```bash
oneleet coverage check --json
oneleet hipaa report --json
oneleet ops workforce-summary --json
oneleet vendor-risk report --json
oneleet trust readiness --json
oneleet security remediation-queue --json
```

Default list commands use summarized rows with local `ref` values instead of raw upstream IDs. Use `--raw` only for short-lived local debugging, and do not paste raw output into reports or commits.
