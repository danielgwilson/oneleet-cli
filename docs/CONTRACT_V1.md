# CONTRACT V1

## Output

Commands with `--json` print exactly one JSON object to stdout.

Success:

```json
{
  "ok": true,
  "data": {}
}
```

Failure:

```json
{
  "ok": false,
  "error": {
    "code": "AUTH_INVALID",
    "message": "unauthorized",
    "retryable": false,
    "http": {
      "status": 401
    }
  }
}
```

## Exit codes

- `0`: success
- `1`: execution or upstream failure
- `2`: auth missing/invalid or user action required

## Stable error codes

- `AUTH_MISSING`
- `AUTH_INVALID`
- `NOT_FOUND`
- `RATE_LIMITED`
- `TIMEOUT`
- `UPSTREAM_5XX`
- `VALIDATION`
- `CHECK_FAILED`
- `UNKNOWN`

## Auth precedence

1. `ONELEET_APP_COOKIE` and `ONELEET_TENANT_ID`
2. `~/.config/oneleet/config.json`

The CLI never accepts session cookies as command-line flags.

`ONELEET_API_BASE_URL` is allowed only for the default Oneleet HTTPS API host
family unless `ONELEET_ALLOW_UNSAFE_API_BASE_URL=1` is set for synthetic local
tests. The CLI must not send a Oneleet session cookie to arbitrary hosts by
default.

Auth status and doctor output use display paths such as
`~/.config/oneleet/config.json` or `$XDG_CONFIG_HOME/oneleet/config.json`, not
machine-local absolute paths.

## V1 supported reads

- current user
- current tenant
- dashboard
- adapter coverage check
- HIPAA aggregate report
- workforce aggregate summary
- vendor-risk aggregate report
- trust readiness aggregate report
- security remediation aggregate queue
- monitors, including monitor detail and linked-control reads
- controls, including sanitized reviewer feedback traversal for matching controls and attached-check reads
- evidence
- policies and policy types
- compliance frameworks
- access reviews
- domains
- integrations
- risk assessments
- security training modules and progress
- tenant members
- vendors
- trust center config, documents, document requests, FAQs, and security issues
- reports
- active pentest request
- code security scan, settings, and repositories
- attack-surface summary, issues, and scans
- arbitrary read-only `/api/v1/...` GET paths through `api get`

## V1 supported mutations

Write commands are dry-run by default and require exact `--write --confirm ...`
confirmation before sending a mutation:

- evidence upload and evidence-to-control/vendor linking
- policy signature-audience updates
- access-review empty-vendor mark-as-reviewed updates
- risk updates, risk archive, and risk-to-control linking
- `monitors refresh <monitor-ref>` using a safe local ref from `monitors list`
- monitor rerun
- monitor enable/disable
- monitor snooze/unsnooze
- monitor config patching
- monitor asset ignore/unignore

Control-check relationship unlinking is not part of V1; the observed Oneleet
frontend exposes `controls checks` and `monitors controls` reads, but no typed
unlink route.

`api get` is an unsafe raw-output escape hatch. It requires `--unsafe-raw` and should not be used for normal report generation.

## Sensitive output defaults

- `people list` summarizes rows by default; pass `--raw` for upstream rows.
- `evidence list` summarizes rows by default; pass `--raw` for upstream rows.
- `security-training progress` summarizes rows by default; pass `--raw` for upstream rows.
- `whoami`, `tenant get`, `frameworks list`, `controls list`, `controls checks`, `controls feedback`, `monitors list`, `monitors get`, `monitors controls`, `monitors refresh`, `vendors list`, `domains list`, `integrations list`, `policies list`, `access-reviews list`, `risk-assessments list`, `reports list`, trust-center row commands, `pentests active-request`, `code-security scan`, `code-security repositories`, `attack-surface issues`, and `attack-surface scans` summarize by default where upstream rows may expose identity, tenant, domain, URL, file, or raw finding details. Pass `--raw` only for narrow local debugging where available.
- Evidence and risk write workflow outputs may include the affected upstream IDs needed for follow-up writes, but must not print cookies, raw tenant exports, local paths, or unrequested raw payloads.
- Default summarized list rows expose local `ref` values and `hasId` booleans instead of raw upstream IDs. These refs are stable only for that command output.
- `controls feedback` defaults to controls with `NEEDS_CHANGES` status, fetches control detail rows, redacts sensitive patterns from reviewer/evidence-request free text, and omits upstream IDs unless explicitly run with `--show-ids`.
- `controls checks` and `monitors controls` omit upstream relationship IDs unless explicitly run with `--show-ids`.
- `hipaa report`, `ops workforce-summary`, `vendor-risk report`, `trust readiness`, and `security remediation-queue` are aggregate-only and should be preferred for scenario reports.

## HIPAA Report Completeness

`hipaa report --json` includes `data.completeness`:

- `complete`: false if optional source reads failed or the report intentionally did not fetch all paginated rows.
- `sourceErrors`: sanitized source/error-code pairs.
- `shapeErrors`: sanitized source/schema-shape pairs for malformed private API list responses.
- `paginationGaps`: sanitized returned-vs-total counts.

Required report sources fail the command. Optional source failures, malformed list shapes, and pagination gaps are surfaced through `complete: false`.

`coverage check` and the other aggregate scenario reports use the same completeness shape and the same safety posture: if output would include emails, URLs, cookies, UUID/internal IDs, or local absolute paths, the command fails closed with `CHECK_FAILED`.
