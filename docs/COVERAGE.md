# COVERAGE

This matrix maps the current Oneleet agent scenarios to the commands exposed by
`oneleet-cli`. It is based on the current `README.md`, packaged skill, and V1
contract.

This is not full Oneleet private API coverage. The CLI is a read-only,
private-surface adapter for the current agent workflows. Detail pages, nested
relationships, private API drift detection, and all mutations remain out of
scope unless added by a separate decision.

## Grade Key

- `A`: safe and repeatable for the named scenario.
- `B`: usable for broad readout, but missing drill-down or filter coverage.
- `C`: inventory-level only; enough to orient, not enough to complete the job.
- `Out of scope`: intentionally unsupported in V1.

## Scenario Matrix

| Scenario | Current commands | Grade | Missing next commands | Safety posture |
| --- | --- | --- | --- | --- |
| Session health and auth validation | `auth status`, `auth import-cdp`, `auth clear`, `doctor`, `whoami`, `tenant get` | A | No blocking V1 command. Future convenience could add browser-profile/session setup helpers if CDP import becomes brittle. | Cookie input is env/config only, never flags. Status/doctor expose booleans and validity, not cookie fragments or tenant IDs. `doctor` fails closed on invalid auth. |
| Typed surface drift canary | `coverage check` | A- | Source-level schema snapshots and endpoint-by-field ownership map. | Safe aggregate canary across typed reads. Emits source status, row counts, scenario grades, and completeness; runtime safety gate blocks sensitive strings. |
| HIPAA posture report | `hipaa report --json`, `hipaa report --format markdown --out <path> --json` | A for the report workflow | `coverage hipaa` or a machine-readable field-to-endpoint map; typed detail commands for controls, monitors, evidence, vendors, reports, and attack-surface rows. | Aggregate and sanitized by design. Includes completeness metadata for source errors, malformed shapes, and pagination gaps. Runtime safety gate rejects emails, URLs, cookies, UUID/internal IDs, and local paths in report output. |
| Dashboard and compliance summary | `dashboard`, `frameworks list`, `controls list`, `monitors list` | A- | Framework-scoped filters, trend/history reads, and detail-by-ID commands for dashboard-linked rows. | Summarized JSON defaults. Use `--raw` only for narrow local debugging where available. |
| Compliance program inspection | `controls list`, `monitors list`, `evidence list`, `policies list`, `policies types`, `frameworks list`, `access-reviews list`, `risk-assessments list`, `reports list` | B | `controls get <id>`, `monitors get <id>`, `evidence get <id>`, `evidence links`, `reports get <id>`, typed pagination/filter/sort options. Evidence-control/vendor attachment route discovery is still needed. | Read-only. Evidence and policy outputs are summarized by default. No binary evidence downloads or full evidence payload retention in normal workflows. |
| Workforce, access, and training operations | `ops workforce-summary`, `people list`, `security-training modules`, `security-training progress`, `access-reviews list`, `integrations list`, `monitors list` | A- for aggregate triage, B for follow-up execution | `people invites`, `groups list`, `vendor-accounts list`, `people get <id>`, `security-training progress --filter`, safe redacted action queues, and access-review detail commands. | Aggregate summary has a runtime safety gate. Identity-shaped rows are summarized by default; raw people/training rows require explicit `--raw` and should not be pasted into reports. |
| Vendor risk, privacy, BAA, and data inventory | `vendor-risk report`, `vendors list`, `evidence list`, `access-reviews list`, `risk-assessments list`, `policies list`, `trust documents`, `reports list` | A- for aggregate triage, C for detailed BAA/privacy proof | `data-inventory summary`, BAA/privacy classification, `vendors get <id>`, safe service/location aggregation, and evidence-to-vendor relationship detail. | Aggregate report has a runtime safety gate. Vendor rows summarize names, URLs, services, locations, and evidence as booleans/counts. |
| Security remediation operations | `security remediation-queue`, `attack-surface summary`, `attack-surface issues --limit <n>`, `attack-surface scans --limit <n>`, `code-security scan`, `code-security settings`, `code-security repositories`, `pentests active-request`, `domains list`, `integrations list`, `controls list`, `monitors list` | A- for remediation lane triage, C for execution/verification | `attack-surface issue get <id>`, redacted target labels, `attack-surface targets`, `attack-surface services`, code-security finding/detail commands, pentest history/findings, and typed remediation owner fields. | Aggregate queue has a runtime safety gate. No scan launch, finding acknowledgement, pentest mutation, or remediation action commands. |
| Trust center and customer security packet | `trust readiness`, `trust config`, `trust documents`, `trust document-requests`, `trust faqs`, `trust security-issues`, `reports list`, `hipaa report` | A- for internal readiness triage, C for public/customer proof | Public trust-center validation, report/document safe metadata, safe downloads/manifests, customer security packet builder, and external sharing checks. | Aggregate readiness report has a runtime safety gate. Trust rows summarize sensitive URLs/files/details by default. |
| Uncovered private API reads | `api get /api/v1/... --unsafe-raw --json` | C | Promote recurring paths into typed commands with summaries, pagination, validation, and tests. | Escape hatch only. Requires `--unsafe-raw`, emits raw private API payloads, and should not be used for normal report workflows. Any report dependency on `api get` is a typed-coverage gap. |
| Mutations and administrative actions | None | Out of scope | Separate decision needed before invites, policy edits/approvals, evidence upload/linking, access-review creation, report generation, trust-center publication, scan launch, or remediation actions. | V1 is read-only. Do not add write commands without a new safety model and explicit approval. |

## Publishability Read

The CLI is strong enough for a sanitized HIPAA posture report and broad security
readout. It is not yet whole-platform complete. The main remaining gaps are
typed detail-by-ID commands, pagination/filter/sort controls, evidence
relationship coverage, public trust-center validation, schema drift checks, and
safe metadata handling for downloadable reports or documents.

Private endpoint shape can change without notice because no confirmed public
Oneleet customer API contract exists for these workflows.

For source or tarball sharing, run `npm run check:release` from this package.
That gate includes tests, package-surface checks, and the repo-local secret
sweep. The package is structurally ready for npm, but publication should still
be a deliberate decision because the adapter targets a private Oneleet web
surface.
