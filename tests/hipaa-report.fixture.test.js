import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { mkdtemp, readFile, rm } from "node:fs/promises";
import http from "node:http";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import test from "node:test";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const packageRoot = path.resolve(__dirname, "..");
const cliPath = path.join(packageRoot, "dist", "cli.js");
const tenantId = "00000000-0000-4000-8000-000000000001";
const fakeCookie = "synthetic-cookie-do-not-leak";
const uuidPattern = /\b[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}\b/i;

const sensitiveValues = [
  tenantId,
  fakeCookie,
  "ada@example.test",
  "Grace Hopper",
  "phi-patient-list.csv",
  "https://patient.example.test/phi",
  "secret-live-report.pdf",
  "Sensitive Vendor LLC",
];

const hipaaRequiredPaths = [
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
];

test("cli help command stays available", async () => {
  const result = await runCli(["--help"], { PATH: process.env.PATH || "" });
  assert.equal(result.code, 0, result.stderr);
  assert.match(result.stdout, /Agent-first private-surface CLI/);
});

test("hipaa report regression fixture keeps denominator and sanitation guarantees", async () => {
  const server = await startFixtureServer();
  const tempConfigHome = await mkdtemp(path.join(os.tmpdir(), "oneleet-cli-test-"));

  try {
    const result = await runCli(["hipaa", "report", "--json"], {
      ONELEET_APP_COOKIE: fakeCookie,
      ONELEET_TENANT_ID: tenantId,
      ONELEET_API_BASE_URL: server.url,
      ONELEET_ALLOW_UNSAFE_API_BASE_URL: "1",
      ONELEET_APP_BASE_URL: "http://127.0.0.1/oneleet-app-fixture",
      XDG_CONFIG_HOME: tempConfigHome,
      HOME: tempConfigHome,
      PATH: process.env.PATH || "",
    });

    assert.equal(result.code, 0, result.stderr);
    assert.equal(result.stderr, "");

    const payload = JSON.parse(result.stdout);
    assert.equal(payload.ok, true);
    assert.equal(payload.data.tenantIdConfigured, true);
    assert.deepEqual(payload.data.completeness, { complete: true, sourceErrors: [], shapeErrors: [], paginationGaps: [] });

    assert.equal(payload.data.controls.total, 65);
    assert.equal(payload.data.controls.hipaaMappedTotal, 64);
    assert.equal(payload.data.controls.unmappedIncluded.length, 1);
    assert.equal(payload.data.controls.unmappedIncluded[0].title, "Vulnerabilities remediated");
    assert.deepEqual(payload.data.controls.unmappedIncluded[0].references, []);
    assert.equal(payload.data.controls.byStatus.find((row) => row.name === "FAILING")?.count, 1);
    assert.equal(payload.data.controls.byStatus.find((row) => row.name === "PASSING")?.count, 64);
    assert.equal(payload.data.controls.failing.length, 1);
    assert.equal("id" in payload.data.controls.failing[0], false);

    assert.equal(payload.data.policies.total, 0);
    assert.equal(payload.data.pentests.hasActiveRequest, false);
    assert.equal(payload.data.codeSecurity.hasScan, false);
    assert.deepEqual(payload.data.codeSecurity.settingsKeys, []);
    assert.equal(payload.data.codeSecurity.repositoryCount, 0);

    assert.equal(/[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}/i.test(result.stdout), false);
    assert.equal(/https?:\/\//i.test(result.stdout), false);
    assert.equal(uuidPattern.test(result.stdout), false);
    assert.equal(result.stdout.includes("oneleet-app"), false);
    for (const value of sensitiveValues) {
      assert.equal(result.stdout.includes(value), false, `default output leaked synthetic sensitive value: ${value}`);
    }

    assert.deepEqual(server.unexpectedPaths, []);
    assertRequiredPathsHit(server.requests, hipaaRequiredPaths);
  } finally {
    await server.close();
    await rm(tempConfigHome, { recursive: true, force: true });
  }
});

test("hipaa markdown report writes sanitized artifact", async () => {
  const server = await startFixtureServer();
  const tempConfigHome = await mkdtemp(path.join(os.tmpdir(), "oneleet-cli-test-"));
  const outPath = path.join(tempConfigHome, "hipaa.md");

  try {
    const result = await runCli(["hipaa", "report", "--format", "markdown", "--out", outPath, "--json"], {
      ONELEET_APP_COOKIE: fakeCookie,
      ONELEET_TENANT_ID: tenantId,
      ONELEET_API_BASE_URL: server.url,
      ONELEET_ALLOW_UNSAFE_API_BASE_URL: "1",
      ONELEET_APP_BASE_URL: "http://127.0.0.1/oneleet-app-fixture",
      XDG_CONFIG_HOME: tempConfigHome,
      HOME: tempConfigHome,
      PATH: process.env.PATH || "",
    });

    assert.equal(result.code, 0, result.stderr);
    const payload = JSON.parse(result.stdout);
    assert.deepEqual(payload, { ok: true, data: { format: "markdown", written: true } });

    const markdown = await readFile(outPath, "utf8");
    assert.match(markdown, /# HIPAA Compliance Report/);
    assert.match(markdown, /Report completeness/);
    assert.match(markdown, /Complete/);
    assert.match(markdown, /Vulnerabilities remediated/);
    assert.equal(/[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}/i.test(markdown), false);
    assert.equal(/https?:\/\//i.test(markdown), false);
    assert.equal(uuidPattern.test(markdown), false);
    for (const value of sensitiveValues) {
      assert.equal(markdown.includes(value), false, `markdown leaked synthetic sensitive value: ${value}`);
    }
  } finally {
    await server.close();
    await rm(tempConfigHome, { recursive: true, force: true });
  }
});

test("hipaa report marks optional source failures incomplete", async () => {
  const server = await startFixtureServer({
    [`/api/v1/tenants/${tenantId}/policies`]: { status: 500, body: { message: "synthetic policies failure" } },
  });
  const tempConfigHome = await mkdtemp(path.join(os.tmpdir(), "oneleet-cli-test-"));

  try {
    const result = await runCli(["hipaa", "report", "--json"], fixtureEnv(server.url, tempConfigHome));
    assert.equal(result.code, 0, result.stderr);
    const payload = JSON.parse(result.stdout);
    assert.equal(payload.ok, true);
    assert.equal(payload.data.completeness.complete, false);
    assert.deepEqual(payload.data.completeness.sourceErrors.find((row) => row.source === "policies"), {
      source: "policies",
      code: "UPSTREAM_5XX",
      retryable: true,
    });
  } finally {
    await server.close();
    await rm(tempConfigHome, { recursive: true, force: true });
  }
});

test("hipaa report marks pagination gaps incomplete beyond attack surface", async () => {
  const server = await startFixtureServer({
    [`/api/v1/tenants/${tenantId}/evidence`]: {
      status: 200,
      body: {
        rows: [{ id: "evidence-1", type: "UPLOAD", aiReviewStatus: "APPROVED", controlIds: [], vendorIds: [] }],
        pagination: { total: 2 },
      },
    },
  });
  const tempConfigHome = await mkdtemp(path.join(os.tmpdir(), "oneleet-cli-test-"));

  try {
    const result = await runCli(["hipaa", "report", "--json"], fixtureEnv(server.url, tempConfigHome));
    assert.equal(result.code, 0, result.stderr);
    const payload = JSON.parse(result.stdout);
    assert.equal(payload.ok, true);
    assert.equal(payload.data.completeness.complete, false);
    assert.deepEqual(payload.data.completeness.paginationGaps.find((row) => row.source === "evidence"), {
      source: "evidence",
      returned: 1,
      total: 2,
    });
  } finally {
    await server.close();
    await rm(tempConfigHome, { recursive: true, force: true });
  }
});

test("hipaa report marks malformed list shapes incomplete", async () => {
  const server = await startFixtureServer({
    [`/api/v1/tenants/${tenantId}/vendors`]: {
      status: 200,
      body: { items: [{ id: "vendor-1", status: "APPROVED" }] },
    },
  });
  const tempConfigHome = await mkdtemp(path.join(os.tmpdir(), "oneleet-cli-test-"));

  try {
    const result = await runCli(["hipaa", "report", "--json"], fixtureEnv(server.url, tempConfigHome));
    assert.equal(result.code, 0, result.stderr);
    const payload = JSON.parse(result.stdout);
    assert.equal(payload.ok, true);
    assert.equal(payload.data.completeness.complete, false);
    assert.deepEqual(payload.data.completeness.shapeErrors.find((row) => row.source === "vendors"), {
      source: "vendors",
      code: "SHAPE_MISMATCH",
    });
  } finally {
    await server.close();
    await rm(tempConfigHome, { recursive: true, force: true });
  }
});

test("hipaa report fails closed if aggregate output contains unsafe identifiers", async () => {
  const server = await startFixtureServer({
    [`/api/v1/tenants/${tenantId}/dashboard`]: {
      status: 200,
      body: {
        data: {
          dashboardStats: {
            frameworks: [
              {
                name: "HIPAA",
                status: "https://patient.example.test/unsafe",
                passingControlsCount: 64,
                totalControlsCount: 64,
              },
            ],
          },
          completedControlsCount: 64,
          totalControlsCount: 65,
        },
      },
    },
  });
  const tempConfigHome = await mkdtemp(path.join(os.tmpdir(), "oneleet-cli-test-"));

  try {
    const result = await runCli(["hipaa", "report", "--json"], fixtureEnv(server.url, tempConfigHome));
    assert.equal(result.code, 1);
    const payload = JSON.parse(result.stdout);
    assert.equal(payload.ok, false);
    assert.equal(payload.error.code, "CHECK_FAILED");
    assert.match(payload.error.message, /safety gate/i);
  } finally {
    await server.close();
    await rm(tempConfigHome, { recursive: true, force: true });
  }
});

test("scenario aggregate reports are sanitized and complete", async () => {
  const server = await startFixtureServer();
  const tempConfigHome = await mkdtemp(path.join(os.tmpdir(), "oneleet-cli-test-"));

  try {
    for (const args of [
      ["ops", "workforce-summary", "--json"],
      ["vendor-risk", "report", "--json"],
      ["trust", "readiness", "--json"],
      ["security", "remediation-queue", "--json"],
    ]) {
      const result = await runCli(args, fixtureEnv(server.url, tempConfigHome));
      assert.equal(result.code, 0, `${args.join(" ")} failed: ${result.stderr || result.stdout}`);
      const payload = JSON.parse(result.stdout);
      assert.equal(payload.ok, true);
      assert.equal(payload.data.completeness.complete, true);
      assert.equal(/[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}/i.test(result.stdout), false);
      assert.equal(/https?:\/\//i.test(result.stdout), false);
      assert.equal(uuidPattern.test(result.stdout), false);
      for (const value of sensitiveValues) {
        assert.equal(result.stdout.includes(value), false, `${args.join(" ")} leaked synthetic sensitive value: ${value}`);
      }
    }
  } finally {
    await server.close();
    await rm(tempConfigHome, { recursive: true, force: true });
  }
});

test("scenario aggregate reports fail closed on unsafe aggregate values", async () => {
  const server = await startFixtureServer({
    [`/api/v1/tenants/${tenantId}/vendors`]: {
      status: 200,
      body: {
        rows: [{ id: "vendor-unsafe", status: "IN_REVIEW", risk: "https://patient.example.test/unsafe" }],
      },
    },
  });
  const tempConfigHome = await mkdtemp(path.join(os.tmpdir(), "oneleet-cli-test-"));

  try {
    const result = await runCli(["vendor-risk", "report", "--json"], fixtureEnv(server.url, tempConfigHome));
    assert.equal(result.code, 1);
    const payload = JSON.parse(result.stdout);
    assert.equal(payload.ok, false);
    assert.equal(payload.error.code, "CHECK_FAILED");
    assert.match(payload.error.message, /safety gate/i);
  } finally {
    await server.close();
    await rm(tempConfigHome, { recursive: true, force: true });
  }
});

test("doctor fails closed for invalid auth", async () => {
  const server = await startRejectingServer(401);
  const tempConfigHome = await mkdtemp(path.join(os.tmpdir(), "oneleet-cli-test-"));

  try {
    const result = await runCli(["doctor", "--json"], {
      ONELEET_APP_COOKIE: fakeCookie,
      ONELEET_TENANT_ID: tenantId,
      ONELEET_API_BASE_URL: server.url,
      ONELEET_ALLOW_UNSAFE_API_BASE_URL: "1",
      ONELEET_APP_BASE_URL: "http://127.0.0.1/oneleet-app-fixture",
      XDG_CONFIG_HOME: tempConfigHome,
      HOME: tempConfigHome,
      PATH: process.env.PATH || "",
    });

    assert.equal(result.code, 2);
    const payload = JSON.parse(result.stdout);
    assert.equal(payload.ok, false);
    assert.equal(payload.error.code, "AUTH_INVALID");
  } finally {
    await server.close();
    await rm(tempConfigHome, { recursive: true, force: true });
  }
});

test("doctor refuses to send cookies to non-Oneleet API hosts unless explicitly allowed", async () => {
  const tempConfigHome = await mkdtemp(path.join(os.tmpdir(), "oneleet-cli-test-"));

  try {
    const result = await runCli(["doctor", "--json"], {
      ONELEET_APP_COOKIE: fakeCookie,
      ONELEET_TENANT_ID: tenantId,
      ONELEET_API_BASE_URL: "http://127.0.0.1:9",
      ONELEET_APP_BASE_URL: "http://127.0.0.1/oneleet-app-fixture",
      XDG_CONFIG_HOME: tempConfigHome,
      HOME: tempConfigHome,
      PATH: process.env.PATH || "",
    });

    assert.equal(result.code, 1);
    assert.equal(result.stderr, "");
    const payload = JSON.parse(result.stdout);
    assert.equal(payload.ok, false);
    assert.equal(payload.error.code, "VALIDATION");
    assert.match(payload.error.message, /non-Oneleet API host/);
  } finally {
    await rm(tempConfigHome, { recursive: true, force: true });
  }
});

test("raw api escape hatch is gated and validates paths", async () => {
  const blocked = await runCli(["api", "get", "/api/v1/users/current", "--json"], { PATH: process.env.PATH || "" });
  assert.equal(blocked.code, 1);
  const blockedPayload = JSON.parse(blocked.stdout);
  assert.equal(blockedPayload.ok, false);
  assert.equal(blockedPayload.error.code, "VALIDATION");

  const invalidPath = await runCli(["api", "get", "/not-api", "--unsafe-raw", "--json"], {
    ONELEET_APP_COOKIE: fakeCookie,
    ONELEET_TENANT_ID: tenantId,
    PATH: process.env.PATH || "",
  });
  assert.equal(invalidPath.code, 1);
  const invalidPathPayload = JSON.parse(invalidPath.stdout);
  assert.equal(invalidPathPayload.ok, false);
  assert.equal(invalidPathPayload.error.code, "VALIDATION");

  const invalidQuery = await runCli(["api", "get", "/api/v1/users/current", "--unsafe-raw", "--query", "badpair", "--json"], {
    ONELEET_APP_COOKIE: fakeCookie,
    ONELEET_TENANT_ID: tenantId,
    PATH: process.env.PATH || "",
  });
  assert.equal(invalidQuery.code, 1);
  const invalidQueryPayload = JSON.parse(invalidQuery.stdout);
  assert.equal(invalidQueryPayload.ok, false);
  assert.equal(invalidQueryPayload.error.code, "VALIDATION");
});

function buildControlsFixture() {
  const rows = [];
  for (let index = 1; index <= 64; index += 1) {
    rows.push({
      id: `control-hipaa-${String(index).padStart(2, "0")}`,
      title: `HIPAA Synthetic Control ${index}`,
      category: index % 2 === 0 ? "ADMINISTRATIVE" : "TECHNICAL",
      status: "PASSING",
      ownerEmail: "ada@example.test",
      tenantComplianceRequirements: [{ frameworkName: "HIPAA", referenceId: `164.${index}` }],
      checkSummary: index % 5 === 0 ? null : { totalChecksCount: 1, passingChecksCount: 1, checksPassingPercentage: 100 },
      evidence: [{ fileName: "phi-patient-list.csv", url: "https://patient.example.test/phi" }],
      evidenceRequests: [],
    });
  }

  rows.push({
    id: "control-unmapped-remediation",
    title: "Vulnerabilities remediated",
    category: "VULNERABILITY_MANAGEMENT",
    status: "FAILING",
    assignee: { name: "Grace Hopper", email: "ada@example.test" },
    tenantComplianceRequirements: [],
    checkSummary: null,
    evidence: [{ fileName: "secret-live-report.pdf", url: "https://patient.example.test/phi" }],
    evidenceRequests: [{ id: "synthetic-request-1", requestedByEmail: "ada@example.test" }],
  });

  return { rows };
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

function fixtureFor(pathname, routeOverrides = {}) {
  const tenantPrefix = tenantPath("");
  const routes = {
    [`${tenantPrefix}/dashboard`]: {
      data: {
        dashboardStats: {
          frameworks: [
            {
              name: "HIPAA",
              passingControlsCount: 64,
              totalControlsCount: 64,
              tenantFramework: {
                id: "synthetic-tenant-framework",
                framework: { id: "hipaa_v1", icon: "https://patient.example.test/hipaa-icon.png" },
              },
            },
          ],
          people: { active: 1, inactive: 1 },
          vulnerabilities: { open: 1, critical: 0 },
          vendors: { incomplete: 1, complete: 0 },
        },
        completedControlsCount: 64,
        totalControlsCount: 65,
      },
    },
    [`${tenantPrefix}/controls/program`]: buildControlsFixture(),
    [`${tenantPrefix}/monitors`]: {
      rows: [
        {
          id: "monitor-1",
          status: "ALERTING",
          monitorType: { name: "Synthetic vulnerability monitor" },
          controlSummaries: [{ title: "Vulnerabilities remediated", ownerEmail: "ada@example.test" }],
          stats: { assets: { count: null, failingCount: 1, passingCount: 64, percentPassing: null } },
          latestRun: { status: "COMPLETE" },
          currentState: { status: "OPEN" },
        },
      ],
    },
    [`${tenantPrefix}/members`]: {
      rows: [
        { id: "member-1", status: "ACTIVE", role: "ADMIN", name: "Grace Hopper", email: "ada@example.test" },
        { id: "member-2", status: "INVITED", role: "MEMBER", userPublic: { name: "Ada Lovelace" }, email: "ada@example.test" },
      ],
    },
    [`${tenantPrefix}/vendors`]: {
      rows: [
        {
          id: "vendor-1",
          status: "IN_REVIEW",
          isCompleted: false,
          vendor: { name: "Sensitive Vendor LLC", url: "https://patient.example.test/phi" },
          services: ["billing"],
          processingLocations: ["US"],
          evidence: [{ fileName: "secret-live-report.pdf" }],
          usesDataInventory: true,
        },
      ],
    },
    [`${tenantPrefix}/evidence`]: {
      rows: [
        {
          id: "evidence-1",
          type: "UPLOAD",
          aiReviewStatus: "APPROVED",
          controlIds: ["control-hipaa-01"],
          vendorIds: ["vendor-1"],
          fileName: "phi-patient-list.csv",
          createdBy: { name: "Grace Hopper", email: "ada@example.test" },
        },
      ],
    },
    [`${tenantPrefix}/policies`]: { rows: null },
    [`${tenantPrefix}/tenant-compliance-frameworks`]: { rows: [{ name: "HIPAA" }] },
    [`${tenantPrefix}/access-reviews`]: { rows: [{ id: "access-review-1", status: "OPEN", reviewerEmail: "ada@example.test" }] },
    [`${tenantPrefix}/domains`]: { rows: [{ id: "domain-1", status: "ACTIVE", domain: "https://patient.example.test/phi" }] },
    [`${tenantPrefix}/integrations`]: {
      rows: [{ id: "integration-1", integrationType: { category: "IDENTITY", name: "Identity Provider" }, connections: [{ status: "FAILED" }] }],
    },
    [`${tenantPrefix}/risk-assessments`]: { rows: [] },
    [`${tenantPrefix}/security-training-modules`]: [],
    [`${tenantPrefix}/security-training-modules/user-progress`]: { rows: [{ id: "progress-1", isCompliant: false, email: "ada@example.test" }] },
    [`${tenantPrefix}/trust/config`]: { isPublished: true, email: "ada@example.test" },
    [`${tenantPrefix}/trust-documents`]: { rows: [{ id: "trust-doc-1", title: "secret-live-report.pdf" }] },
    [`${tenantPrefix}/trust-document-requests`]: { rows: [] },
    [`${tenantPrefix}/trust-faqs`]: { rows: [] },
    [`${tenantPrefix}/trust-security-issues`]: { rows: [] },
    [`${tenantPrefix}/reports`]: { rows: [{ id: "report-1", status: "READY", fileName: "secret-live-report.pdf" }] },
    [`${tenantPrefix}/code-security-settings`]: null,
    [`${tenantPrefix}/git-repository`]: { rows: null },
    [`${tenantPrefix}/ng-attack-surface/dashboard/stats`]: { assetCount: null, issueCount: 0, lastScanCompletedAt: null },
    [`${tenantPrefix}/ng-attack-surface/issues`]: { issues: [], pagination: { total: 0 } },
    [`${tenantPrefix}/ng-attack-surface/scans`]: { scans: [], pagination: { total: 0 } },
  };

  if (Object.prototype.hasOwnProperty.call(routeOverrides, pathname)) {
    return routeOverrides[pathname];
  }

  if (pathname === `${tenantPrefix}/pentest-scheduling-requests/active` || pathname === `${tenantPrefix}/code-security-scan`) {
    return { status: 204, body: "" };
  }

  return pathname in routes ? { status: 200, body: routes[pathname] } : null;
}

async function startFixtureServer(routeOverrides = {}) {
  const requests = [];
  const unexpectedPaths = [];
  const server = http.createServer((request, response) => {
    const url = new URL(request.url || "/", "http://127.0.0.1");
    requests.push(url.pathname);
    const fixture = fixtureFor(url.pathname, routeOverrides);
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
    unexpectedPaths,
    close: () => new Promise((resolve, reject) => server.close((error) => (error ? reject(error) : resolve()))),
  };
}

function assertRequiredPathsHit(requests, requiredPaths) {
  for (const requiredPath of requiredPaths) {
    assert.ok(requests.includes(requiredPath), `expected synthetic fixture path to be read: ${requiredPath}`);
  }
}

async function startRejectingServer(status) {
  const server = http.createServer((request, response) => {
    response.writeHead(status, { "content-type": "application/json" });
    response.end(JSON.stringify({ message: "unauthorized" }));
  });

  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  const address = server.address();
  assert(address && typeof address === "object");
  return {
    url: `http://127.0.0.1:${address.port}`,
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
