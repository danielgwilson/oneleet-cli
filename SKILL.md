---
name: oneleet
description: "Use the Oneleet CLI to inspect Oneleet security and compliance posture through an unofficial read-only private-surface adapter. Prefer summarized JSON and aggregate reports; never print cookies or raw sensitive payloads."
---

# Oneleet CLI Skill

Use this skill for Oneleet compliance, HIPAA, security posture, trust-center,
vendor, people, evidence, monitor, control, attack-surface, code-security, or
platform-coverage analysis.

## Command

Prefer an installed binary:

```bash
oneleet --help
```

For one-off package use after publication:

```bash
npx -y oneleet-cli --help
```

For a source checkout:

```bash
npm install
npm run build
node dist/cli.js --help
```

## Safety Rules

- Do not print, paste, store, or commit the `oneleet-app` cookie.
- Do not commit raw HARs, browser traces, screenshots, storage state, cookie
  dumps, or full upstream JSON exports.
- Prefer aggregate reports and summarized list outputs.
- Use `--raw` and `api get --unsafe-raw` only for short-lived local debugging.
- Default summarized list rows use local `ref` labels and `hasId` booleans
  instead of raw upstream IDs.
- Reports should use counts, statuses, categories, and control titles. Avoid
  names, emails, tenant IDs, filenames, raw URLs, raw upstream IDs, and raw
  evidence text.

## First Checks

```bash
oneleet auth status --json
oneleet doctor --json
```

If auth is missing, ask Daniel to log into Oneleet in Chrome with remote
debugging enabled, then import:

```bash
oneleet auth import-cdp --port 9333 --json
```

## Best Starting Commands

```bash
oneleet coverage check --json
oneleet hipaa report --json
oneleet ops workforce-summary --json
oneleet vendor-risk report --json
oneleet trust readiness --json
oneleet security remediation-queue --json
```

Treat scenario reports as coverage for current workflows, not full Oneleet
private API coverage. If a scenario still needs raw detail, record it as a typed
CLI gap before using `api get`.
