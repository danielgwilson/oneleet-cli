# oneleet-cli

Agent-first private-surface CLI for Oneleet read workflows and narrow monitor refreshes.

This is an unofficial adapter. It is not affiliated with, endorsed by, or an
official API wrapper for Oneleet. It uses Oneleet private web API surfaces and
can drift when Oneleet changes the app.

## Current scope

- browser/CDP-assisted auth import
- session health checks
- current user and tenant reads
- dashboard, HIPAA aggregate report, controls, sanitized control feedback traversal, monitors, evidence, policies, frameworks, people, vendors, domains, integrations, access reviews, risk assessments, security training, trust center, reports, pentests, code security, and attack-surface reads
- guarded control review requests and evidence writes for uploading file evidence to controls and linking existing evidence to controls or vendors
- guarded risk reads/updates for assessment triage
- narrow `monitors refresh <monitor-ref>` rerun trigger for an existing monitor
- read-only `/api/v1/...` escape hatch for uncovered Oneleet private API paths

V1 is read-first. Mutations are limited to explicit typed workflow commands.
Evidence and risk writes are dry-run by default and require `--write` plus an
exact `--confirm ...` value. `monitors refresh` only triggers Oneleet's own
rerun endpoint for a monitor that already appears in the configured tenant's
monitor list. Do not add broader mutations without a separate decision.

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
oneleet monitors get <monitor-id> --json
oneleet monitors controls <monitor-id> --show-ids --json
oneleet monitors refresh monitor-014 --wait 120 --json
oneleet monitors rerun <monitor-id> --write --confirm <monitor-id> --json
oneleet monitors set-enabled <monitor-id> --enabled false --disabled-reason "Reason" --write --confirm <monitor-id> --json
oneleet monitors snooze <monitor-id> --until 2026-06-30T00:00:00Z --reason "Reason" --write --confirm <monitor-id> --json
oneleet monitors unsnooze <monitor-id> --write --confirm <monitor-id> --json
oneleet monitors set-config <monitor-id> --config-json '{"key":"value"}' --write --confirm <monitor-id> --json
oneleet monitors update-assets-ignore-status <monitor-id> --ignore-asset-id <asset-instance-id> --reason "Reason" --write --confirm <monitor-id> --json
oneleet controls list --json
oneleet controls checks <control-id> --show-ids --json
oneleet controls feedback --json
oneleet controls feedback --status NEEDS_CHANGES --show-ids --json
oneleet controls request-review <control-id> --json
oneleet controls request-review <control-id> --write --confirm <control-id> --json
oneleet evidence list --json
oneleet evidence list --raw --json
oneleet evidence get <evidence-id> --json
oneleet evidence upload ./register.csv --control-id <control-id> --link-control-id <control-id> --json
oneleet evidence upload ./register.csv --control-id <control-id> --link-control-id <control-id> --write --confirm register.csv --json
oneleet evidence link-control <evidence-id> --control-id <control-id> --json
oneleet evidence link-control <evidence-id> --control-id <control-id> --write --confirm <evidence-id> --json
oneleet evidence link-vendor <evidence-id> --vendor-id <tenant-vendor-id> --json
oneleet evidence link-vendor <evidence-id> --vendor-id <tenant-vendor-id> --write --confirm <evidence-id> --json
oneleet policies list --json
oneleet policies types --json
oneleet policies set-audience <policy-id> --audience GROUPS --json
oneleet policies set-audience <policy-id> --audience GROUPS --write --confirm <policy-id> --json
oneleet policies set-audience <policy-id> --audience EVERYONE --write --confirm <policy-id> --json
oneleet frameworks list --json
oneleet access-reviews list --json
oneleet access-reviews mark-empty-vendors-reviewed <access-review-id> --json
oneleet access-reviews mark-empty-vendors-reviewed <access-review-id> --write --confirm <access-review-id> --json
oneleet domains list --json
oneleet integrations list --json
oneleet risk-assessments list --json
oneleet risks get <risk-id> --json
oneleet risks update <risk-id> --response MITIGATE --response-details "Mitigation summary" --json
oneleet risks update <risk-id> --response MITIGATE --response-details "Mitigation summary" --write --confirm <risk-id> --json
oneleet risks archive <risk-id> --json
oneleet risks archive <risk-id> --write --confirm <risk-id> --json
oneleet risks link-controls <risk-id> --control-id <control-id> --json
oneleet risks link-controls <risk-id> --control-id <control-id> --write --confirm <risk-id> --json
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
- read-only by default; write commands are opt-in and require `--write` plus exact confirmation
- `monitors refresh` is an explicit rerun trigger and never accepts raw upstream IDs by default
- refuses to send the session cookie to non-Oneleet API hosts unless explicitly opted into for synthetic local tests
- `api get` is an unsafe raw-output escape hatch and requires `--unsafe-raw`
- no raw HARs, screenshots, storage state, or full recon dumps in repo
- `monitors refresh` accepts local `monitor-###` refs from `monitors list`; it resolves the upstream id internally and does not print upstream ids by default
- people, evidence, and security-training progress output is summarized by default; use `--raw` only when you need full upstream rows
- tenant, current-user, controls, control feedback, monitors, vendors, domains, integrations, policies, access reviews, reports, trust-center rows, pentest requests, code-security rows, attack-surface issues, and attack-surface scans are also summarized by default where the upstream shape may contain sensitive or noisy details
- default summarized list rows use local `ref` values and `hasId` booleans instead of raw upstream IDs; pass `--raw` only for short-lived local debugging
- `controls feedback` defaults to `NEEDS_CHANGES`, traverses the control-detail endpoint, redacts sensitive patterns from reviewer/evidence-request free text, and omits raw IDs unless `--show-ids` is provided for follow-up writes
- `coverage check`, `hipaa report`, `ops workforce-summary`, `vendor-risk report`, `trust readiness`, and `security remediation-queue` are intentionally aggregate/sanitized and avoid names, emails, cookies, URLs, UUID/internal IDs, and raw evidence filenames
- evidence, policy, risk, and monitor write commands intentionally return the affected IDs needed for follow-up writes, but never print cookies
- `hipaa report` includes `data.completeness`; treat `sourceErrors`, `shapeErrors`, or `paginationGaps` as report caveats before drawing conclusions

## Evidence write workflow

Evidence writes are meant for cases where a local artifact needs to become
control or vendor evidence without hand-clicking through Oneleet. Upload is
dry-run by default:

```bash
oneleet evidence upload ./baa-register.csv \
  --control-id <business-associate-agreements-managed-control-id> \
  --link-control-id <business-associate-agreements-with-subcontractors-control-id> \
  --link-control-id <vendor-management-control-id> \
  --reuse-existing-name \
  --json
```

To write, repeat the command with the generated confirmation string:

```bash
oneleet evidence upload ./baa-register.csv \
  --control-id <business-associate-agreements-managed-control-id> \
  --link-control-id <business-associate-agreements-with-subcontractors-control-id> \
  --link-control-id <vendor-management-control-id> \
  --reuse-existing-name \
  --write \
  --confirm baa-register.csv \
  --json
```

Existing evidence can be linked without re-uploading:

```bash
oneleet evidence link-control <evidence-id> --control-id <control-id> --write --confirm <evidence-id> --json
oneleet evidence link-vendor <evidence-id> --vendor-id <tenant-vendor-id> --write --confirm <evidence-id> --json
```

## Monitor write workflow

Monitor writes expose the same private endpoints used by the Oneleet app for
reruns, enable/disable, snooze/unsnooze, config patching, and asset
ignore/unignore. They are dry-run by default and require exact monitor-id
confirmation before sending a write:

```bash
oneleet monitors controls <monitor-id> --show-ids --json
oneleet controls checks <control-id> --show-ids --json
oneleet monitors rerun <monitor-id> --write --confirm <monitor-id> --json
oneleet monitors update-assets-ignore-status <monitor-id> \
  --ignore-asset-id <asset-instance-id> \
  --reason "Documented exception" \
  --write \
  --confirm <monitor-id> \
  --json
```

The current Oneleet frontend exposes control-check relationship reads
(`controls checks`, `monitors controls`) but does not expose a typed
monitor-control unlink route.

## Contract

See [docs/CONTRACT_V1.md](./docs/CONTRACT_V1.md).

## Release Hygiene

See [docs/PUBLISHING.md](./docs/PUBLISHING.md). The short gate is:

```bash
npm run check:release
```
