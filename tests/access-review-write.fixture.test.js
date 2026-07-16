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
const accessReviewId = "00000000-0000-4000-8000-000000000701";
const pendingEmptyVendorId = "00000000-0000-4000-8000-000000000801";
const reviewedEmptyVendorId = "00000000-0000-4000-8000-000000000802";
const pendingAccountVendorId = "00000000-0000-4000-8000-000000000803";
const fakeCookie = "synthetic-cookie-do-not-leak";

test("access review empty-vendor review is dry-run by default", async () => {
  const server = await startAccessReviewServer();
  const tempConfigHome = await mkdtemp(path.join(os.tmpdir(), "oneleet-cli-access-review-dry-run-"));

  try {
    const result = await runCli(
      ["access-reviews", "mark-empty-vendors-reviewed", accessReviewId, "--note", "No detected accounts", "--json"],
      fixtureEnv(server.url, tempConfigHome),
    );

    assert.equal(result.code, 0, result.stderr || result.stdout);
    assert.equal(result.stderr, "");
    const payload = JSON.parse(result.stdout);
    assert.equal(payload.ok, true);
    assert.equal(payload.data.dryRun, true);
    assert.equal(payload.data.accessReviewId, accessReviewId);
    assert.equal(payload.data.note, "No detected accounts");
    assert.equal(payload.data.summary.vendorCount, 3);
    assert.equal(payload.data.summary.zeroAccountVendorCount, 2);
    assert.equal(payload.data.summary.targetCount, 1);
    assert.equal(payload.data.summary.alreadyReviewedZeroAccountVendorCount, 1);
    assert.equal(payload.data.summary.skippedWithAccountsCount, 1);
    assert.equal(payload.data.targets[0].ref, "access-review-vendor-001");
    assert.equal(payload.data.targets[0].hasId, true);
    assert.equal(payload.data.targets[0].accountCount, 0);
    assert.match(payload.data.writeRequired, new RegExp(`--write --confirm ${accessReviewId}`));
    assert.deepEqual(server.requests.map((request) => request.method + " " + request.pathname), [
      `GET /api/v1/access-reviews/${accessReviewId}`,
    ]);
    assert.equal(result.stdout.includes(fakeCookie), false);
  } finally {
    await server.close();
    await rm(tempConfigHome, { recursive: true, force: true });
  }
});

test("access review empty-vendor review marks only pending vendors with no accounts", async () => {
  const server = await startAccessReviewServer();
  const tempConfigHome = await mkdtemp(path.join(os.tmpdir(), "oneleet-cli-access-review-write-"));

  try {
    const result = await runCli(
      [
        "access-reviews",
        "mark-empty-vendors-reviewed",
        accessReviewId,
        "--note",
        "No detected accounts",
        "--write",
        "--confirm",
        accessReviewId,
        "--json",
      ],
      fixtureEnv(server.url, tempConfigHome),
    );

    assert.equal(result.code, 0, result.stderr || result.stdout);
    assert.equal(result.stderr, "");
    const payload = JSON.parse(result.stdout);
    assert.equal(payload.ok, true);
    assert.equal(payload.data.dryRun, false);
    assert.equal(payload.data.writtenCount, 1);
    assert.equal(payload.data.summary.targetCount, 1);
    assert.equal(payload.data.after.summary.targetCount, 0);
    assert.equal(payload.data.after.summary.alreadyReviewedZeroAccountVendorCount, 2);
    assert.deepEqual(server.requests.map((request) => request.method + " " + request.pathname), [
      `GET /api/v1/access-reviews/${accessReviewId}`,
      `POST /api/v1/access-review-vendors/${pendingEmptyVendorId}/mark-as-reviewed`,
      `GET /api/v1/access-reviews/${accessReviewId}`,
    ]);
    assert.equal(server.markReviewedBodies.length, 1);
    assert.equal(server.markReviewedBodies[0].includes("No detected accounts"), true);
    assert.equal(result.stdout.includes(fakeCookie), false);
  } finally {
    await server.close();
    await rm(tempConfigHome, { recursive: true, force: true });
  }
});

async function startAccessReviewServer() {
  const requests = [];
  const markReviewedBodies = [];
  const reviewedVendorIds = new Set([reviewedEmptyVendorId]);

  const server = http.createServer(async (request, response) => {
    const url = new URL(request.url || "/", "http://127.0.0.1");
    requests.push({ method: request.method, pathname: url.pathname });

    if (request.method === "GET" && url.pathname === `/api/v1/access-reviews/${accessReviewId}`) {
      writeJson(response, accessReviewFixture(reviewedVendorIds));
      return;
    }

    if (request.method === "POST" && url.pathname === `/api/v1/access-review-vendors/${pendingEmptyVendorId}/mark-as-reviewed`) {
      markReviewedBodies.push(await readRequestBody(request));
      reviewedVendorIds.add(pendingEmptyVendorId);
      writeJson(response, { ok: true });
      return;
    }

    response.writeHead(404, { "content-type": "application/json" });
    response.end(JSON.stringify({ error: "unexpected fixture path", path: url.pathname }));
  });

  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  const address = server.address();
  assert(address && typeof address === "object");
  return {
    url: `http://127.0.0.1:${address.port}`,
    requests,
    markReviewedBodies,
    close: () => new Promise((resolve, reject) => server.close((error) => (error ? reject(error) : resolve()))),
  };
}

function accessReviewFixture(reviewedVendorIds) {
  return {
    data: {
      id: accessReviewId,
      title: "Synthetic Access Review",
      status: "IN_PROGRESS",
      vendors: [
        accessReviewVendorFixture(pendingEmptyVendorId, reviewedVendorIds.has(pendingEmptyVendorId), []),
        accessReviewVendorFixture(reviewedEmptyVendorId, reviewedVendorIds.has(reviewedEmptyVendorId), []),
        accessReviewVendorFixture(pendingAccountVendorId, reviewedVendorIds.has(pendingAccountVendorId), [
          { id: "00000000-0000-4000-8000-000000000901", isActive: true },
        ]),
      ],
    },
  };
}

function accessReviewVendorFixture(id, reviewed, accounts) {
  return {
    id,
    status: reviewed ? "REVIEWED" : "NOT_STARTED",
    reviewedAt: reviewed ? "2026-06-16T18:00:00.000Z" : undefined,
    tenantVendorId: id.replace("8000", "9000"),
    risk: "LOW",
    reviewer: { id: "00000000-0000-4000-8000-000000000902" },
    vendor: { id: id.replace("8000", "9001"), name: "Synthetic Vendor" },
    accessReviewAccounts: accounts,
  };
}

function readRequestBody(request) {
  return new Promise((resolve, reject) => {
    let body = "";
    request.setEncoding("utf8");
    request.on("data", (chunk) => {
      body += chunk;
    });
    request.on("error", reject);
    request.on("end", () => resolve(body));
  });
}

function writeJson(response, body) {
  response.writeHead(200, { "content-type": "application/json" });
  response.end(JSON.stringify(body));
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
