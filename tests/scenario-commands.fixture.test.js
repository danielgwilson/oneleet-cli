import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { mkdtemp, rm } from "node:fs/promises";
import http from "node:http";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import test from "node:test";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const packageRoot = path.resolve(__dirname, "..");
const cliPath = path.join(packageRoot, "dist", "cli.js");
const tenantId = "00000000-0000-4000-8000-000000000001";
const monitorId = "00000000-0000-4000-8000-000000000101";
const fakeCookie = "synthetic-cookie-do-not-leak";
const uuidPattern = /\b[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}\b/i;

const sensitiveValues = [
  tenantId,
  fakeCookie,
  "ada@example.test",
  "grace@example.test",
  "linus@example.test",
  "Grace Hopper",
  "Ada Lovelace",
  "Linus Torvalds",
  "Sensitive Vendor LLC",
  "Critical Processor Inc",
  "Dormant Vendor Co",
  "phi-patient-list.csv",
  "secret-live-report.pdf",
  "remediation-export.csv",
  "https://patient.example.test/phi",
  "https://critical-vendor.example.test",
  "https://app.example.test/admin",
];

const upstreamIdentifierValues = [
  tenantId,
  "access-review-1",
  "attack-issue-1",
  "code-scan-1",
  "control-failing-1",
  "domain-1",
  "evidence-1",
  "integration-1",
  "member-1",
  "module-1",
  "monitor-1",
  "progress-1",
  "repo-1",
  "report-1",
  "risk-1",
  "scan-1",
  "trust-doc-1",
  "trust-request-1",
  "vendor-1",
];

const scenarios = [
  {
    name: "coverage check",
    args: ["coverage", "check"],
    requiredPaths: [
      tenantPath("/dashboard"),
      tenantPath("/controls/program"),
      tenantPath("/monitors"),
      tenantPath("/members"),
      tenantPath("/vendors"),
      tenantPath("/evidence"),
      tenantPath("/policies"),
      tenantPath("/tenant-compliance-frameworks"),
      tenantPath("/access-reviews"),
      tenantPath("/domains"),
      tenantPath("/integrations"),
      tenantPath("/risk-assessments"),
      tenantPath("/security-training-modules"),
      tenantPath("/security-training-modules/user-progress"),
      tenantPath("/trust/config"),
      tenantPath("/trust-documents"),
      tenantPath("/trust-document-requests"),
      tenantPath("/trust-faqs"),
      tenantPath("/trust-security-issues"),
      tenantPath("/reports"),
      tenantPath("/pentest-scheduling-requests/active"),
      tenantPath("/code-security-scan"),
      tenantPath("/code-security-settings"),
      tenantPath("/git-repository"),
      tenantPath("/ng-attack-surface/dashboard/stats"),
      tenantPath("/ng-attack-surface/issues"),
      tenantPath("/ng-attack-surface/scans"),
    ],
    assertPayload: assertCoverageCheck,
  },
  {
    name: "ops workforce-summary",
    args: ["ops", "workforce-summary"],
    requiredPaths: [
      tenantPath("/members"),
      tenantPath("/access-reviews"),
      tenantPath("/security-training-modules"),
      tenantPath("/security-training-modules/user-progress"),
      tenantPath("/monitors"),
      tenantPath("/integrations"),
    ],
    assertPayload: assertOpsWorkforceSummary,
  },
  {
    name: "vendor-risk report",
    args: ["vendor-risk", "report"],
    requiredPaths: [
      tenantPath("/vendors"),
      tenantPath("/evidence"),
      tenantPath("/access-reviews"),
      tenantPath("/risk-assessments"),
      tenantPath("/policies"),
      tenantPath("/trust-documents"),
      tenantPath("/reports"),
    ],
    assertPayload: assertVendorRiskReport,
  },
  {
    name: "trust readiness",
    args: ["trust", "readiness"],
    requiredPaths: [
      tenantPath("/trust/config"),
      tenantPath("/trust-documents"),
      tenantPath("/trust-document-requests"),
      tenantPath("/trust-faqs"),
      tenantPath("/trust-security-issues"),
      tenantPath("/reports"),
      tenantPath("/policies"),
      tenantPath("/evidence"),
      tenantPath("/controls/program"),
      tenantPath("/monitors"),
      tenantPath("/security-training-modules/user-progress"),
      tenantPath("/ng-attack-surface/dashboard/stats"),
      tenantPath("/ng-attack-surface/issues"),
      tenantPath("/code-security-scan"),
      tenantPath("/pentest-scheduling-requests/active"),
    ],
    assertPayload: assertTrustReadiness,
  },
  {
    name: "security remediation-queue",
    args: ["security", "remediation-queue"],
    requiredPaths: [
      tenantPath("/controls/program"),
      tenantPath("/monitors"),
      tenantPath("/integrations"),
      tenantPath("/domains"),
      tenantPath("/ng-attack-surface/dashboard/stats"),
      tenantPath("/ng-attack-surface/issues"),
      tenantPath("/ng-attack-surface/scans"),
      tenantPath("/code-security-scan"),
      tenantPath("/code-security-settings"),
      tenantPath("/git-repository"),
      tenantPath("/pentest-scheduling-requests/active"),
    ],
    assertPayload: assertSecurityRemediationQueue,
  },
];

for (const scenario of scenarios) {
  test(`${scenario.name} synthetic fixture contract`, async () => {
    const server = await startFixtureServer();
    const tempConfigHome = await mkdtemp(path.join(os.tmpdir(), "oneleet-cli-scenario-test-"));

    try {
      const result = await runCli([...scenario.args, "--json"], fixtureEnv(server.url, tempConfigHome));
      assert.equal(result.code, 0, result.stderr);
      assert.equal(result.stderr, "");

      const payload = JSON.parse(result.stdout);
      assertScenarioEnvelope(payload);
      scenario.assertPayload(payload.data);
      assertSafeAggregateOutput(result.stdout);

      assert.deepEqual(server.unexpectedPaths, []);
      assertRequiredPathsHit(server.requests, scenario.requiredPaths);
    } finally {
      await server.close();
      await rm(tempConfigHome, { recursive: true, force: true });
    }
  });
}

test("json parser errors use the JSON failure envelope", async () => {
  for (const args of [
    ["vendors", "--json"],
    ["people", "list", "--wat", "--json"],
    ["attack-surface", "issues", "--limit", "abc", "--json"],
  ]) {
    const result = await runCli(args, { PATH: process.env.PATH || "" });
    assert.equal(result.code, 1, `${args.join(" ")} should fail validation`);
    assert.equal(result.stderr, "");
    const payload = JSON.parse(result.stdout);
    assert.equal(payload.ok, false);
    assert.equal(payload.error.code, "VALIDATION");
  }
});

test("default list summaries redact upstream identifiers and sensitive fields", async () => {
  const summaryCommands = [
    ["controls", "list"],
    ["monitors", "list"],
    ["people", "list"],
    ["vendors", "list"],
    ["evidence", "list"],
    ["policies", "list"],
    ["frameworks", "list"],
    ["access-reviews", "list"],
    ["domains", "list"],
    ["integrations", "list"],
    ["risk-assessments", "list"],
    ["security-training", "modules"],
    ["security-training", "progress"],
    ["trust", "config"],
    ["trust", "documents"],
    ["trust", "document-requests"],
    ["trust", "faqs"],
    ["trust", "security-issues"],
    ["reports", "list"],
    ["pentests", "active-request"],
    ["code-security", "scan"],
    ["code-security", "repositories"],
    ["attack-surface", "issues", "--limit", "50"],
    ["attack-surface", "scans", "--limit", "50"],
  ];
  const server = await startFixtureServer();
  const tempConfigHome = await mkdtemp(path.join(os.tmpdir(), "oneleet-cli-summary-test-"));

  try {
    for (const command of summaryCommands) {
      const result = await runCli([...command, "--json"], fixtureEnv(server.url, tempConfigHome));
      assert.equal(result.code, 0, `${command.join(" ")} failed: ${result.stderr}`);
      assert.equal(result.stderr, "");
      const payload = JSON.parse(result.stdout);
      assert.equal(payload.ok, true, `${command.join(" ")} did not return ok envelope`);
      assertSafeSummaryOutput(result.stdout, command.join(" "));
    }
  } finally {
    await server.close();
    await rm(tempConfigHome, { recursive: true, force: true });
  }
});

test("monitor refresh uses a local ref and redacts upstream identifiers", async () => {
  const server = await startFixtureServer();
  const tempConfigHome = await mkdtemp(path.join(os.tmpdir(), "oneleet-cli-refresh-test-"));

  try {
    const result = await runCli(["monitors", "refresh", "monitor-001", "--json"], fixtureEnv(server.url, tempConfigHome));
    assert.equal(result.code, 0, result.stderr);
    assert.equal(result.stderr, "");

    const payload = JSON.parse(result.stdout);
    assert.equal(payload.ok, true);
    assert.equal(payload.data.triggered, true);
    assert.deepEqual(payload.data.selector, { mode: "ref", ref: "monitor-001", hasId: true });
    assert.equal(payload.data.wait.reason, "not-requested");
    assert.equal(payload.data.before.ref, "monitor-001");
    assert.equal(payload.data.after.ref, "monitor-001");
    assertSafeSummaryOutput(result.stdout, "monitors refresh");

    assert.ok(server.requests.includes(`/api/v1/monitors/${monitorId}/rerun`), "expected monitor rerun endpoint to be called");
    assert.ok(
      server.requestLog.find((entry) => entry.method === "POST" && entry.pathname === `/api/v1/monitors/${monitorId}/rerun`),
      "expected monitor rerun endpoint to use POST",
    );
  } finally {
    await server.close();
    await rm(tempConfigHome, { recursive: true, force: true });
  }
});

function assertScenarioEnvelope(payload) {
  assert.equal(payload.ok, true);
  assert.equal(typeof payload.data, "object");
  assert.deepEqual(payload.data.completeness, { complete: true, sourceErrors: [], shapeErrors: [], paginationGaps: [] });
}

function assertOpsWorkforceSummary(data) {
  const workforce = requiredSection(data, ["workforce", "people", "members"]);
  assert.equal(readNumber(workforce, ["total", "memberCount", "workforceCount"]), 3);
  assert.equal(readNamedCount(workforce.byStatus, "ACTIVE"), 1);
  assert.equal(readNamedCount(workforce.byStatus, "INVITED"), 1);
  assert.equal(readNamedCount(workforce.byStatus, "DISABLED"), 1);

  const securityTraining = requiredSection(data, ["securityTraining", "training"]);
  assert.equal(readNumber(securityTraining, ["userProgressCount", "progressCount", "total"]), 3);
  assert.equal(readNamedCount(securityTraining.progressByCompliance || securityTraining.byCompliance, "NON_COMPLIANT"), 2);

  const accessReviews = requiredSection(data, ["accessReviews", "accessReview"]);
  assert.equal(readNumberOrNamedCount(accessReviews, ["openCount", "open"], "OPEN"), 1);
}

function assertCoverageCheck(data) {
  assert.ok(Array.isArray(data.sources), "missing source status rows");
  assert.ok(Array.isArray(data.scenarios), "missing scenario rows");
  assert.equal(data.sources.every((row) => row.ok === true), true);
  assert.ok(data.sources.find((row) => row.source === "people" && row.rowCount === 3));
  assert.ok(data.sources.find((row) => row.source === "attackSurfaceIssues" && row.rowCount === 3 && row.total === 3));
  assert.ok(data.scenarios.find((row) => row.name === "vendor-risk-privacy" && row.status === "implemented"));
  assert.ok(data.scenarios.find((row) => row.name === "detail-drilldown" && row.status === "queued"));
}

function assertVendorRiskReport(data) {
  const vendors = requiredSection(data, ["vendors", "vendorRisk"]);
  assert.equal(readNumber(vendors, ["total", "vendorCount"]), 3);
  assert.equal(readNamedCount(vendors.byStatus, "IN_REVIEW"), 1);
  assert.equal(readNamedCount(vendors.byStatus, "APPROVED"), 1);
  assert.equal(readNamedCount(vendors.byStatus, "NOT_STARTED"), 1);
  assert.equal(readNamedCount(vendors.byRisk, "CRITICAL"), 1);
  assert.equal(readNamedCount(vendors.byRisk, "HIGH"), 1);
  assert.equal(readNumber(vendors, ["withEvidence", "vendorsWithEvidence", "evidenceLinkedCount"]), 2);
  assert.equal(readNumber(vendors, ["completed"]), 1);

  const evidence = requiredSection(data, ["evidence"]);
  assert.equal(readNumber(evidence, ["total"]), 2);
  assert.equal(readNumber(evidence, ["attachedToVendors"]), 2);

  const relatedProgramInputs = requiredSection(data, ["relatedProgramInputs"]);
  assert.equal(readNumber(relatedProgramInputs, ["accessReviewCount"]), 2);
  assert.equal(readNumber(relatedProgramInputs, ["riskAssessmentCount"]), 2);
  assert.equal(readNumber(relatedProgramInputs, ["policyCount"]), 0);
  assert.equal(readNumber(relatedProgramInputs, ["trustDocumentCount"]), 2);
  assert.equal(readNumber(relatedProgramInputs, ["reportCount"]), 2);
}

function assertTrustReadiness(data) {
  const trustCenter = requiredSection(data, ["trustCenter", "trust", "readiness"]);
  assert.equal(readBoolean(trustCenter, ["published", "isPublished"]), false);
  assert.equal(readNumber(trustCenter, ["documentCount", "documents"]), 2);
  assert.equal(readNumber(trustCenter, ["documentRequestCount", "requests", "pendingRequestCount"]), 1);
  assert.equal(readNumber(trustCenter, ["faqCount", "faqs"]), 1);
  assert.equal(readNumber(trustCenter, ["securityIssueCount", "issues"]), 1);

  const ready = data.ready ?? data.readiness?.ready ?? data.readiness?.customerReady ?? trustCenter.ready;
  assert.equal(ready, false);
  assert.equal(readNumber(data.readiness, ["blockerCount"]), 7);

  const packetInputs = requiredSection(data, ["packetInputs"]);
  assert.equal(readNumber(packetInputs, ["policyCount"]), 0);
  assert.equal(readNumber(packetInputs, ["evidenceCount"]), 2);
  assert.equal(readNumber(packetInputs, ["controlsFailing"]), 2);
  assert.equal(readNumber(packetInputs, ["monitorProblemCount"]), 1);
  assert.equal(readNumber(packetInputs, ["nonCompliantTrainingUsers"]), 2);
  assert.equal(readNumber(packetInputs, ["openAttackSurfaceIssues"]), 2);
  assert.equal(readBoolean(packetInputs, ["codeSecurityScanPresent"]), true);
  assert.equal(readBoolean(packetInputs, ["activePentestRequestPresent"]), false);
}

function assertSecurityRemediationQueue(data) {
  const controls = requiredSection(data, ["controls", "controlRemediation"]);
  assert.equal(readNumber(controls, ["failing"]), 2);

  const monitors = requiredSection(data, ["monitors", "monitorRemediation"]);
  assert.equal(readNumber(monitors, ["problemCount", "alertingCount"]), 1);

  const attackSurface = requiredSection(data, ["attackSurface", "attackSurfaceIssues"]);
  assert.equal(readNumberOrNamedCount(attackSurface, ["openIssueCount", "unresolvedIssueCount"], "OPEN"), 2);

  const codeSecurity = requiredSection(data, ["codeSecurity"]);
  assert.equal(readBoolean(codeSecurity, ["scanPresent"]), true);
  assert.equal(readNumber(codeSecurity, ["repositoryCount"]), 1);
  assert.equal(readBoolean(codeSecurity, ["settingsPresent"]), true);

  const lanes = data.lanes;
  assert.ok(Array.isArray(lanes), "missing remediation lanes");
  assert.deepEqual(lanes.map((row) => row.lane), ["controls", "monitors", "attack-surface", "integrations", "pentest"]);
  assert.equal(lanes.reduce((sum, row) => sum + row.count, 0), 7);
}

function assertSafeAggregateOutput(output) {
  assert.equal(/[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}/i.test(output), false);
  assert.equal(/https?:\/\//i.test(output), false);
  assert.equal(/oneleet-app=/i.test(output), false);
  assert.equal(uuidPattern.test(output), false);
  assert.equal(/\/Users\/[A-Za-z0-9._-]+\//.test(output), false);
  for (const value of sensitiveValues) {
    assert.equal(output.includes(value), false, `scenario output leaked synthetic sensitive value: ${value}`);
  }
}

function assertSafeSummaryOutput(output, commandName) {
  assertSafeAggregateOutput(output);
  for (const value of upstreamIdentifierValues) {
    assert.equal(output.includes(value), false, `${commandName} leaked upstream identifier: ${value}`);
  }
}

function requiredSection(data, names) {
  for (const name of names) {
    if (data && data[name] && typeof data[name] === "object") return data[name];
  }
  assert.fail(`missing expected section; tried ${names.join(", ")}`);
}

function readNumber(object, names) {
  for (const name of names) {
    if (typeof object?.[name] === "number") return object[name];
  }
  assert.fail(`missing expected numeric field; tried ${names.join(", ")}`);
}

function readBoolean(object, names) {
  for (const name of names) {
    if (typeof object?.[name] === "boolean") return object[name];
  }
  assert.fail(`missing expected boolean field; tried ${names.join(", ")}`);
}

function readNamedCount(rows, name) {
  assert.ok(Array.isArray(rows), `missing count array for ${name}`);
  const row = rows.find((entry) => entry?.name === name);
  assert.ok(row, `missing count row ${name}`);
  assert.equal(typeof row.count, "number", `missing numeric count for ${name}`);
  return row.count;
}

function readNumberOrNamedCount(object, numberFields, countName) {
  for (const field of numberFields) {
    if (typeof object?.[field] === "number") return object[field];
  }
  return readNamedCount(object?.byStatus || object?.byState || object?.counts, countName);
}

function readNumberOrArrayLength(object, numberFields, arrayField) {
  for (const field of numberFields) {
    if (typeof object?.[field] === "number") return object[field];
  }
  if (Array.isArray(object?.[arrayField])) return object[arrayField].length;
  assert.fail(`missing expected numeric or array field; tried ${numberFields.join(", ")} or ${arrayField}`);
}

function assertRequiredPathsHit(requests, requiredPaths) {
  for (const requiredPath of requiredPaths) {
    assert.ok(requests.includes(requiredPath), `expected synthetic fixture path to be read: ${requiredPath}`);
  }
}

function fixtureEnv(serverUrl, tempConfigHome) {
  return {
    ONELEET_APP_COOKIE: fakeCookie,
    ONELEET_TENANT_ID: tenantId,
    ONELEET_API_BASE_URL: serverUrl,
    ONELEET_ALLOW_UNSAFE_API_BASE_URL: "1",
    ONELEET_APP_BASE_URL: "http://127.0.0.1/oneleet-app-fixture",
    XDG_CONFIG_HOME: tempConfigHome,
    HOME: tempConfigHome,
    PATH: process.env.PATH || "",
  };
}

function tenantPath(suffix) {
  return `/api/v1/tenants/${tenantId}${suffix}`;
}

function fixtureFor(pathname) {
  const routes = {
    [tenantPath("/dashboard")]: {
      data: {
        dashboardStats: {
          people: { active: 1, inactive: 1, invited: 1 },
          vulnerabilities: { open: 2, critical: 1 },
          vendors: { incomplete: 2, complete: 1 },
        },
        completedControlsCount: 11,
        totalControlsCount: 13,
      },
    },
    [tenantPath("/controls/program")]: {
      rows: [
        {
          id: "control-failing-1",
          title: "Vulnerabilities remediated",
          category: "VULNERABILITY_MANAGEMENT",
          status: "FAILING",
          tenantComplianceRequirements: [{ frameworkName: "SOC 2", referenceId: "CC7.1" }],
          checkSummary: { totalChecksCount: 1, passingChecksCount: 0, checksPassingPercentage: 0 },
          evidence: [{ fileName: "remediation-export.csv", url: "https://patient.example.test/phi" }],
          evidenceRequests: [{ id: "evidence-request-1", requestedByEmail: "ada@example.test" }],
        },
        {
          id: "control-failing-2",
          title: "Code vulnerabilities triaged",
          category: "CODE_SECURITY",
          status: "FAILING",
          tenantComplianceRequirements: [{ frameworkName: "SOC 2", referenceId: "CC7.2" }],
          checkSummary: { totalChecksCount: 2, passingChecksCount: 1, checksPassingPercentage: 50 },
          evidence: [],
          evidenceRequests: [],
        },
        {
          id: "control-passing-1",
          title: "Security training assigned",
          category: "SECURITY_TRAINING",
          status: "PASSING",
          tenantComplianceRequirements: [{ frameworkName: "SOC 2", referenceId: "CC1.4" }],
          checkSummary: { totalChecksCount: 1, passingChecksCount: 1, checksPassingPercentage: 100 },
          evidence: [],
          evidenceRequests: [],
        },
      ],
    },
    [tenantPath("/monitors")]: {
      rows: [
        {
          id: monitorId,
          status: "ALERTING",
          monitorType: { name: "Synthetic vulnerability monitor" },
          controlSummaries: [{ title: "Vulnerabilities remediated", ownerEmail: "ada@example.test" }],
          stats: { assets: { count: 10, failingCount: 2, passingCount: 8, percentPassing: 80 } },
          latestRun: { status: "COMPLETE" },
          currentState: { status: "OPEN" },
        },
        {
          id: "monitor-2",
          status: "OK",
          monitorType: { name: "Synthetic user monitor" },
          controlSummaries: [],
          stats: { assets: { count: 3, failingCount: 0, passingCount: 3, percentPassing: 100 } },
          latestRun: { status: "COMPLETE" },
          currentState: { status: "RESOLVED" },
        },
      ],
    },
    [`/api/v1/monitors/${monitorId}/rerun`]: { accepted: true, latestRunQueued: true, id: "00000000-0000-4000-8000-000000000102" },
    [tenantPath("/members")]: {
      rows: [
        { id: "member-1", status: "ACTIVE", role: "ADMIN", name: "Grace Hopper", email: "grace@example.test" },
        { id: "member-2", status: "INVITED", role: "MEMBER", userPublic: { name: "Ada Lovelace" }, email: "ada@example.test" },
        { id: "member-3", status: "DISABLED", role: "MEMBER", name: "Linus Torvalds", email: "linus@example.test" },
      ],
    },
    [tenantPath("/vendors")]: {
      rows: [
        {
          id: "vendor-1",
          status: "IN_REVIEW",
          isCompleted: false,
          risk: "CRITICAL",
          vendor: { name: "Sensitive Vendor LLC", url: "https://critical-vendor.example.test" },
          services: ["billing"],
          processingLocations: ["US"],
          evidence: [{ fileName: "secret-live-report.pdf" }],
          usesDataInventory: true,
        },
        {
          id: "vendor-2",
          status: "APPROVED",
          isCompleted: true,
          risk: "LOW",
          vendor: { name: "Critical Processor Inc", url: "https://critical-vendor.example.test" },
          services: ["analytics"],
          processingLocations: ["US", "EU"],
          evidence: [{ fileName: "phi-patient-list.csv" }],
          usesDataInventory: true,
        },
        {
          id: "vendor-3",
          status: "NOT_STARTED",
          isCompleted: false,
          risk: "HIGH",
          vendor: { name: "Dormant Vendor Co", url: "https://critical-vendor.example.test" },
          services: [],
          processingLocations: [],
          evidence: [],
          usesDataInventory: false,
        },
      ],
    },
    [tenantPath("/evidence")]: {
      rows: [
        {
          id: "evidence-1",
          type: "UPLOAD",
          aiReviewStatus: "APPROVED",
          controlIds: ["control-failing-1"],
          vendorIds: ["vendor-1"],
          fileName: "phi-patient-list.csv",
          createdBy: { name: "Grace Hopper", email: "grace@example.test" },
        },
        {
          id: "evidence-2",
          type: "REPORT",
          aiReviewStatus: "NEEDS_REVIEW",
          controlIds: [],
          vendorIds: ["vendor-2"],
          fileName: "secret-live-report.pdf",
          createdBy: { name: "Ada Lovelace", email: "ada@example.test" },
        },
      ],
    },
    [tenantPath("/policies")]: { rows: [] },
    [tenantPath("/tenant-compliance-frameworks")]: { rows: [{ name: "SOC 2" }] },
    [tenantPath("/access-reviews")]: {
      rows: [
        { id: "access-review-1", status: "OPEN", reviewerEmail: "ada@example.test" },
        { id: "access-review-2", status: "COMPLETED", reviewerEmail: "grace@example.test" },
      ],
    },
    [tenantPath("/domains")]: {
      rows: [{ id: "domain-1", status: "ACTIVE", domain: "https://patient.example.test/phi" }],
    },
    [tenantPath("/integrations")]: {
      rows: [
        {
          id: "integration-1",
          integrationType: { category: "IDENTITY", name: "Identity Provider" },
          connections: [{ status: "FAILED" }],
        },
      ],
    },
    [tenantPath("/risk-assessments")]: {
      rows: [
        { id: "risk-1", status: "OPEN", risk: "HIGH", title: "Synthetic vendor risk" },
        { id: "risk-2", status: "COMPLETED", risk: "LOW", title: "Synthetic workforce risk" },
      ],
    },
    [tenantPath("/security-training-modules")]: {
      rows: [
        { id: "module-1", title: "HIPAA", lifecycle: "PUBLISHED", audience: "ALL", sections: [{}] },
        { id: "module-2", title: "Secure coding", lifecycle: "DRAFT", audience: "ENGINEERING", sections: [{}] },
      ],
    },
    [tenantPath("/security-training-modules/user-progress")]: {
      rows: [
        { id: "progress-1", isCompliant: true, email: "grace@example.test" },
        { id: "progress-2", isCompliant: false, email: "ada@example.test" },
        { id: "progress-3", isCompliant: false, email: "linus@example.test" },
      ],
    },
    [tenantPath("/trust/config")]: {
      isPublished: false,
      email: "ada@example.test",
      backlink: "https://patient.example.test/phi",
      customTitle: "Sensitive trust center",
    },
    [tenantPath("/trust-documents")]: {
      rows: [
        { id: "trust-doc-1", status: "PUBLISHED", title: "secret-live-report.pdf" },
        { id: "trust-doc-2", status: "DRAFT", title: "remediation-export.csv" },
      ],
    },
    [tenantPath("/trust-document-requests")]: {
      rows: [{ id: "trust-request-1", status: "OPEN", requesterEmail: "ada@example.test" }],
    },
    [tenantPath("/trust-faqs")]: {
      rows: [{ id: "trust-faq-1", status: "PUBLISHED", question: "Do you process PHI?" }],
    },
    [tenantPath("/trust-security-issues")]: {
      rows: [{ id: "trust-issue-1", status: "OPEN", title: "Synthetic issue" }],
    },
    [tenantPath("/reports")]: {
      rows: [
        { id: "report-1", status: "READY", fileName: "secret-live-report.pdf" },
        { id: "report-2", status: "DRAFT", fileName: "remediation-export.csv" },
      ],
    },
    [tenantPath("/code-security-settings")]: { enabled: true, defaultBranchOnly: false },
    [tenantPath("/git-repository")]: {
      rows: [{ id: "repo-1", provider: "GITHUB", status: "CONNECTED", fullName: "secret/repo", url: "https://patient.example.test/phi" }],
    },
    [tenantPath("/ng-attack-surface/dashboard/stats")]: {
      assetCount: 8,
      issueCount: 3,
      lastScanCompletedAt: "2026-05-20T00:00:00.000Z",
    },
    [tenantPath("/ng-attack-surface/issues")]: {
      issues: [
        {
          id: "attack-issue-1",
          title: "Public admin panel",
          severity: "CRITICAL",
          status: "OPEN",
          affectedUrl: "https://app.example.test/admin",
        },
        {
          id: "attack-issue-2",
          title: "Weak TLS",
          severity: "HIGH",
          status: "OPEN",
          affectedUrl: "https://app.example.test/admin",
        },
        {
          id: "attack-issue-3",
          title: "Resolved finding",
          severity: "LOW",
          status: "RESOLVED",
          affectedUrl: "https://app.example.test/admin",
        },
      ],
      pagination: { total: 3 },
    },
    [tenantPath("/ng-attack-surface/scans")]: {
      scans: [
        {
          id: "scan-1",
          status: "COMPLETE",
          totalIssuesFound: 3,
          criticalIssuesFound: 1,
          highIssuesFound: 1,
          targetDomains: ["https://app.example.test/admin"],
        },
      ],
      pagination: { total: 1 },
    },
  };

  if (pathname === tenantPath("/pentest-scheduling-requests/active")) return { status: 204, body: "" };
  if (pathname === tenantPath("/code-security-scan")) {
    return {
      status: 200,
      body: {
        id: "code-scan-1",
        status: "COMPLETE",
        issues: [
          { id: "code-issue-1", severity: "HIGH", status: "OPEN", url: "https://patient.example.test/phi" },
          { id: "code-issue-2", severity: "MEDIUM", status: "OPEN", url: "https://patient.example.test/phi" },
        ],
      },
    };
  }

  return pathname in routes ? { status: 200, body: routes[pathname] } : null;
}

async function startFixtureServer() {
  const requests = [];
  const requestLog = [];
  const unexpectedPaths = [];
  const server = http.createServer((request, response) => {
    const url = new URL(request.url || "/", "http://127.0.0.1");
    requests.push(url.pathname);
    requestLog.push({ method: request.method, pathname: url.pathname });
    const fixture = fixtureFor(url.pathname);
    if (!fixture) {
      unexpectedPaths.push(url.pathname);
      response.writeHead(404, { "content-type": "application/json" });
      response.end(JSON.stringify({ error: "unexpected fixture path", path: url.pathname }));
      return;
    }

    response.writeHead(fixture.status, { "content-type": "application/json" });
    response.end(typeof fixture.body === "string" ? fixture.body : JSON.stringify(fixture.body));
  });

  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  const address = server.address();
  assert(address && typeof address === "object");
  return {
    url: `http://127.0.0.1:${address.port}`,
    requests,
    requestLog,
    unexpectedPaths,
    close: () => new Promise((resolve, reject) => server.close((error) => (error ? reject(error) : resolve()))),
  };
}

function runCli(args, env) {
  return new Promise((resolve, reject) => {
    const child = spawn(process.execPath, [cliPath, ...args], {
      cwd: packageRoot,
      env,
      stdio: ["ignore", "pipe", "pipe"],
    });
    let stdout = "";
    let stderr = "";
    child.stdout.setEncoding("utf8");
    child.stderr.setEncoding("utf8");
    child.stdout.on("data", (chunk) => {
      stdout += chunk;
    });
    child.stderr.on("data", (chunk) => {
      stderr += chunk;
    });
    child.on("error", reject);
    child.on("close", (code) => resolve({ code, stdout, stderr }));
  });
}
