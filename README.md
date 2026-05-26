# oneleet-cli

Agent-first private-surface CLI for Oneleet read workflows.

This is an unofficial adapter. It is not affiliated with, endorsed by, or an
official API wrapper for Oneleet. It uses Oneleet private web API surfaces and
can drift when Oneleet changes the app.

## Current scope

- browser/CDP-assisted auth import
- session health checks
- current user and tenant reads
- dashboard, HIPAA aggregate report, controls, monitors, evidence, policies, frameworks, people, vendors, domains, integrations, access reviews, risk assessments, security training, trust center, reports, pentests, code security, and attack-surface reads
- read-only `/api/v1/...` escape hatch for uncovered Oneleet private API paths

V1 is read-only. Do not add mutations without a separate decision.

## Install

Source checkout:

```bash
npm install
npm run build
node dist/cli.js --help
```

Published package install:

```bash
npm install -g oneleet-cli
oneleet --help
```

Skill install:

```bash
npx -y skills add -g danielgwilson/oneleet-cli --skill oneleet
```

One-off run:

```bash
npx -y oneleet-cli doctor --json
```

Optional local link:

```bash
npm link
```

## Auth

Requires Node.js 22 or newer.

Open a logged-in Chrome session with remote debugging enabled, then import the
`oneleet-app` session cookie:

```bash
oneleet auth import-cdp --port 9333 --json
oneleet doctor --json
```

The saved config lives at:

```text
~/.config/oneleet/config.json
```

It is written with `0600` permissions. Do not commit it.

Ephemeral env auth is also supported:

```bash
export ONELEET_APP_COOKIE=...
export ONELEET_TENANT_ID=...
oneleet doctor --json
```

Do not pass cookie values as CLI flags.

`ONELEET_API_BASE_URL` is only for synthetic local tests and must point at a
Oneleet HTTPS host by default. Non-Oneleet API hosts are rejected unless
`ONELEET_ALLOW_UNSAFE_API_BASE_URL=1` is set.

## Commands

```bash
oneleet auth status --json
oneleet auth clear --json
oneleet doctor --json
oneleet whoami --json
oneleet tenant get --json
oneleet dashboard --json
oneleet coverage check --json
oneleet hipaa report --json
oneleet hipaa report --format markdown --out /tmp/oneleet-hipaa.md --json
oneleet ops workforce-summary --json
oneleet vendor-risk report --json
oneleet trust readiness --json
oneleet security remediation-queue --json
oneleet monitors list --json
oneleet controls list --json
oneleet evidence list --json
oneleet evidence list --raw --json
oneleet policies list --json
oneleet policies types --json
oneleet frameworks list --json
oneleet access-reviews list --json
oneleet domains list --json
oneleet integrations list --json
oneleet risk-assessments list --json
oneleet security-training modules --json
oneleet security-training progress --json
oneleet security-training progress --raw --json
oneleet people list --json
oneleet people list --raw --json
oneleet vendors list --json
oneleet trust config --json
oneleet trust documents --json
oneleet trust document-requests --json
oneleet trust faqs --json
oneleet trust security-issues --json
oneleet reports list --json
oneleet pentests active-request --json
oneleet code-security scan --json
oneleet code-security settings --json
oneleet code-security repositories --json
oneleet attack-surface summary --json
oneleet attack-surface issues --limit 50 --json
oneleet attack-surface scans --limit 50 --json
oneleet api get /api/v1/users/current --unsafe-raw --json
```

## Safety model

- private-surface, cookie-backed API
- read-only by default
- refuses to send the session cookie to non-Oneleet API hosts unless explicitly opted into for synthetic local tests
- `api get` is an unsafe raw-output escape hatch and requires `--unsafe-raw`
- no raw HARs, screenshots, storage state, or full recon dumps in repo
- people, evidence, and security-training progress output is summarized by default; use `--raw` only when you need full upstream rows
- tenant, current-user, controls, monitors, vendors, domains, integrations, policies, access reviews, reports, trust-center rows, pentest requests, code-security rows, attack-surface issues, and attack-surface scans are also summarized by default where the upstream shape may contain sensitive or noisy details
- default summarized list rows use local `ref` values and `hasId` booleans instead of raw upstream IDs; pass `--raw` only for short-lived local debugging
- `coverage check`, `hipaa report`, `ops workforce-summary`, `vendor-risk report`, `trust readiness`, and `security remediation-queue` are intentionally aggregate/sanitized and avoid names, emails, cookies, URLs, UUID/internal IDs, and raw evidence filenames
- `hipaa report` includes `data.completeness`; treat `sourceErrors`, `shapeErrors`, or `paginationGaps` as report caveats before drawing conclusions

## Contract

See [docs/CONTRACT_V1.md](./docs/CONTRACT_V1.md).

## Release Hygiene

See [docs/PUBLISHING.md](./docs/PUBLISHING.md). The short gate is:

```bash
npm run check:release
```
