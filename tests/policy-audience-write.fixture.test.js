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
const policyId = "00000000-0000-4000-8000-000000000301";
const fakeCookie = "synthetic-cookie-do-not-leak";

test("policies set-audience is dry-run by default", async () => {
  const server = await startPolicyServer();
  const tempDir = await mkdtemp(path.join(os.tmpdir(), "oneleet-cli-policy-dry-run-"));
  try {
    const result = await runCli(
      ["policies", "set-audience", policyId, "--audience", "GROUPS", "--json"],
      fixtureEnv(server.url, tempDir),
    );
    assert.equal(result.code, 0, result.stderr || result.stdout);
    assert.equal(result.stderr, "");
    const payload = JSON.parse(result.stdout);
    assert.equal(payload.ok, true);
    assert.equal(payload.data.dryRun, true);
    assert.equal(payload.data.policyId, policyId);
    assert.deepEqual(payload.data.patch, { audience: "GROUPS", groupIds: [] });
    assert.equal(payload.data.before.audience, "EVERYONE");
    assert.match(payload.data.writeRequired, new RegExp(`--write --confirm ${policyId}`));
    // dry-run must not mutate: only the read happened
    assert.deepEqual(server.requests.map((r) => r.method + " " + r.pathname), [`GET /api/v1/policies/${policyId}`]);
    assert.equal(result.stdout.includes(fakeCookie), false);
  } finally {
    await server.close();
    await rm(tempDir, { recursive: true, force: true });
  }
});

test("policies set-audience writes audience=GROUPS with empty groupIds (no required signers)", async () => {
  const server = await startPolicyServer();
  const tempDir = await mkdtemp(path.join(os.tmpdir(), "oneleet-cli-policy-write-"));
  try {
    const result = await runCli(
      ["policies", "set-audience", policyId, "--audience", "GROUPS", "--write", "--confirm", policyId, "--json"],
      fixtureEnv(server.url, tempDir),
    );
    assert.equal(result.code, 0, result.stderr || result.stdout);
    assert.equal(result.stderr, "");
    const payload = JSON.parse(result.stdout);
    assert.equal(payload.ok, true);
    assert.equal(payload.data.dryRun, false);
    assert.deepEqual(payload.data.patch, { audience: "GROUPS", groupIds: [] });
    assert.equal(payload.data.before.audience, "EVERYONE");
    assert.equal(payload.data.after.audience, "GROUPS");
    // name must survive the audience-only update
    assert.equal(payload.data.after.name, payload.data.before.name);
    assert.deepEqual(server.requests.map((r) => r.method + " " + r.pathname), [
      `GET /api/v1/policies/${policyId}`,
      `PATCH /api/v1/policies/${policyId}`,
      `GET /api/v1/policies/${policyId}`,
    ]);
    assert.deepEqual(server.patchBody, { audience: "GROUPS", groupIds: [] });
    assert.equal(result.stdout.includes(fakeCookie), false);
  } finally {
    await server.close();
    await rm(tempDir, { recursive: true, force: true });
  }
});

test("policies set-audience refuses --confirm mismatch and --group-id without GROUPS", async () => {
  const server = await startPolicyServer();
  const tempDir = await mkdtemp(path.join(os.tmpdir(), "oneleet-cli-policy-guard-"));
  try {
    const mismatch = await runCli(
      ["policies", "set-audience", policyId, "--audience", "GROUPS", "--write", "--confirm", "wrong", "--json"],
      fixtureEnv(server.url, tempDir),
    );
    assert.notEqual(mismatch.code, 0);
    assert.match(mismatch.stdout + mismatch.stderr, /--confirm to exactly match/);
    // no PATCH should have been issued on the mismatch
    assert.equal(server.requests.some((r) => r.method === "PATCH"), false);

    const badGroup = await runCli(
      ["policies", "set-audience", policyId, "--audience", "EVERYONE", "--group-id", "00000000-0000-4000-8000-000000000999", "--json"],
      fixtureEnv(server.url, tempDir),
    );
    assert.notEqual(badGroup.code, 0);
    assert.match(badGroup.stdout + badGroup.stderr, /--group-id is only valid with --audience GROUPS/);
  } finally {
    await server.close();
    await rm(tempDir, { recursive: true, force: true });
  }
});

async function startPolicyServer() {
  const requests = [];
  let patchBody = null;
  let audience = "EVERYONE";

  const server = http.createServer(async (request, response) => {
    const url = new URL(request.url || "/", "http://127.0.0.1");
    requests.push({ method: request.method, pathname: url.pathname });

    if (request.method === "GET" && url.pathname === `/api/v1/policies/${policyId}`) {
      writeJson(response, policyObject(audience));
      return;
    }
    if (request.method === "PATCH" && url.pathname === `/api/v1/policies/${policyId}`) {
      patchBody = JSON.parse(await readRequestBody(request));
      if (typeof patchBody.audience === "string") audience = patchBody.audience;
      writeJson(response, policyObject(audience));
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
    get patchBody() {
      return patchBody;
    },
    close: () => new Promise((resolve, reject) => server.close((error) => (error ? reject(error) : resolve()))),
  };
}

function policyObject(audience) {
  return {
    id: policyId,
    name: "Synthetic Data Backup and Recovery Policy",
    audience,
    reviewerType: "NONE",
    tenantId,
    types: [{ id: "dataBackupAndRecovery_v1", name: "Data Backup and Recovery" }],
    currentVersion: {
      id: "00000000-0000-4000-8000-000000000401",
      applicableTenantMembers: audience === "EVERYONE" ? [{ id: "m1" }, { id: "m2" }] : [],
      directSignatures: [{ id: "s1" }],
      isPublished: true,
    },
    updatedAt: "2026-05-31T00:00:00.000Z",
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
