---
name: oneleet
description: "Use the Oneleet CLI to inspect Oneleet security and compliance posture, especially HIPAA controls, monitors, evidence inventory, people/access-review status, trust center, vendors, attack surface, code security, reports, and read-only private API paths. Never print cookies or raw sensitive payloads; prefer summarized outputs and JSON."
---

# Oneleet CLI Skill

Use this skill when Daniel asks for Oneleet compliance, HIPAA, security posture, trust-center, vendor, people, evidence, monitor, control, attack-surface, code-security, or platform-coverage analysis.

## Command

Prefer the installed binary:

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

- Do not print, paste, or store the `oneleet-app` cookie.
- Do not commit raw HARs, browser traces, screenshots, cookie dumps, storage state, or full upstream JSON exports.
- Prefer aggregate/summarized commands for reports.
- Most commands summarize by default when upstream payloads can include identity, tenant, domain, URL, file, or raw finding details. Use `--raw` only for a narrow local debugging reason.
- Default summarized list rows use local `ref` values plus `hasId` booleans instead of raw upstream IDs. Treat those refs as output-local labels, not durable Oneleet IDs.
- Write reports with aggregate counts, categories, statuses, and control titles. Avoid names, emails, tenant IDs, filenames, raw URLs, and raw evidence text unless Daniel explicitly asks.
- This adapter is a private-surface reader. Treat endpoint names and response shapes as fragile.

## First Checks

Always start with:

```bash
oneleet auth status --json
oneleet doctor --json
```

If auth is missing, ask Daniel to log into Oneleet in a Chrome session that has remote debugging enabled, then import:

```bash
oneleet auth import-cdp --port 9333 --json
```

## Best Starting Point For HIPAA

Use the aggregate report first:

```bash
oneleet hipaa report --json
oneleet hipaa report --format markdown --out /tmp/oneleet-hipaa.md --json
```

The report covers:

- HIPAA framework dashboard status
- HIPAA controls by status and category, including a labeled unmapped remediation control when Oneleet's dashboard/control list includes it outside HIPAA framework mappings
- failing, in-progress, and not-started controls
- monitors by status, problem count, problem controls, and summarized monitor problems
- people by status and role
- vendors by status and vendor data completeness
- evidence counts and attachment coverage
- policies, frameworks, access reviews, domains, integrations, risk assessments
- security training modules and progress
- trust center publication and document/request/FAQ/security issue counts
- reports, pentest request status, code security, attack surface issues and scans
- report completeness status, source errors, shape errors, and pagination gaps

## Command Map

Core:

```bash
oneleet whoami --json
oneleet tenant get --json
oneleet dashboard --json
oneleet coverage check --json
oneleet hipaa report --json
oneleet ops workforce-summary --json
oneleet vendor-risk report --json
oneleet trust readiness --json
oneleet security remediation-queue --json
```

Compliance program:

```bash
oneleet frameworks list --json
oneleet controls list --json
oneleet monitors list --json
oneleet evidence list --json
oneleet policies list --json
oneleet policies types --json
oneleet reports list --json
```

Organization and vendors:

```bash
oneleet people list --json
oneleet vendors list --json
oneleet access-reviews list --json
oneleet domains list --json
oneleet integrations list --json
oneleet risk-assessments list --json
```

Training and trust center:

```bash
oneleet security-training modules --json
oneleet security-training progress --json
oneleet trust config --json
oneleet trust documents --json
oneleet trust document-requests --json
oneleet trust faqs --json
oneleet trust security-issues --json
```

Security surfaces:

```bash
oneleet pentests active-request --json
oneleet code-security scan --json
oneleet code-security settings --json
oneleet code-security repositories --json
oneleet attack-surface summary --json
oneleet attack-surface issues --limit 50 --json
oneleet attack-surface scans --limit 50 --json
```

Read-only escape hatch for new Oneleet private API paths:

```bash
oneleet api get /api/v1/users/current --unsafe-raw --json
oneleet api get /api/v1/some/path --query limit=25 --unsafe-raw --json
```

Only use `api get` for local debugging of `GET /api/v1/...` paths discovered from the live app. It emits raw private API payloads, requires `--unsafe-raw`, and is not allowed in normal report workflows. If a report depends on `api get`, record that the endpoint is uncovered by the typed CLI.

## Report Pattern

For a HIPAA deep dive:

1. Run `auth status`, `doctor`, and `hipaa report`.
2. Use typed commands to fill gaps only where the aggregate report is insufficient.
3. Summarize readiness by:
   - control status
   - control category
   - failing controls
   - in-progress controls
   - not-started controls
   - monitor status
   - people/security training status
   - vendor/access review/risk assessment status
   - vulnerabilities, attack surface, pentest, code security
   - evidence/policy/report/trust-center coverage
4. Call out CLI/platform coverage gaps separately from compliance gaps.
5. Check `data.completeness.complete`; if false, report source errors, shape errors, or pagination gaps before drawing conclusions.
6. End with verification commands run and remaining uncertainties.

For broader Oneleet work, start with `coverage check --json`, then prefer composed aggregate reports before individual list commands:

- workforce / access / training follow-up: `ops workforce-summary --json`
- vendor, privacy, data inventory, BAA readiness: `vendor-risk report --json`
- trust center or customer security packet readiness: `trust readiness --json`
- remediation triage across controls, monitors, attack surface, code security, integrations, and pentest: `security remediation-queue --json`

Treat these reports as scenario coverage, not full private API coverage. If a scenario still needs raw detail, record it as a typed CLI gap before using `api get`.
