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
const riskId = "00000000-0000-4000-8000-000000000301";
const primaryControlId = "00000000-0000-4000-8000-000000000401";
const secondaryControlId = "00000000-0000-4000-8000-000000000402";
const fakeCookie = "synthetic-cookie-do-not-leak";

test("risk archive is dry-run by default", async () => {
  const server = await startRiskServer();
  const tempConfigHome = await mkdtemp(path.join(os.tmpdir(), "oneleet-cli-risk-archive-dry-run-"));

  try {
    const result = await runCli(["risks", "archive", riskId, "--json"], fixtureEnv(server.url, tempConfigHome));

    assert.equal(result.code, 0, result.stderr || result.stdout);
    assert.equal(result.stderr, "");
    const payload = JSON.parse(result.stdout);
    assert.equal(payload.ok, true);
    assert.equal(payload.data.dryRun, true);
    assert.equal(payload.data.riskId, riskId);
    assert.equal(payload.data.before.title, "Synthetic Risk");
    assert.match(payload.data.writeRequired, new RegExp(`--write --confirm ${riskId}`));
    assert.deepEqual(server.requests.map((request) => request.method + " " + request.pathname), [`GET /api/v1/risks/${riskId}`]);
    assert.equal(result.stdout.includes(fakeCookie), false);
  } finally {
    await server.close();
    await rm(tempConfigHome, { recursive: true, force: true });
  }
});

test("risk archive writes through the Oneleet risk endpoint", async () => {
  const server = await startRiskServer();
  const tempConfigHome = await mkdtemp(path.join(os.tmpdir(), "oneleet-cli-risk-archive-write-"));

  try {
    const result = await runCli(
      ["risks", "archive", riskId, "--write", "--confirm", riskId, "--json"],
      fixtureEnv(server.url, tempConfigHome),
    );

    assert.equal(result.code, 0, result.stderr || result.stdout);
    assert.equal(result.stderr, "");
    const payload = JSON.parse(result.stdout);
    assert.equal(payload.ok, true);
    assert.equal(payload.data.dryRun, false);
    assert.equal(payload.data.after.archivedAt, "2026-06-18T00:00:00.000Z");
    assert.deepEqual(server.requests.map((request) => request.method + " " + request.pathname), [
      `GET /api/v1/risks/${riskId}`,
      `DELETE /api/v1/risks/${riskId}`,
      `GET /api/v1/risks/${riskId}`,
    ]);
    assert.equal(result.stdout.includes(fakeCookie), false);
  } finally {
    await server.close();
    await rm(tempConfigHome, { recursive: true, force: true });
  }
});

test("risk link-controls appends controls and preserves existing links", async () => {
  const server = await startRiskServer();
  const tempConfigHome = await mkdtemp(path.join(os.tmpdir(), "oneleet-cli-risk-link-controls-"));

  try {
    const result = await runCli(
      [
        "risks",
        "link-controls",
        riskId,
        "--control-id",
        secondaryControlId,
        "--write",
        "--confirm",
        riskId,
        "--json",
      ],
      fixtureEnv(server.url, tempConfigHome),
    );

    assert.equal(result.code, 0, result.stderr || result.stdout);
    assert.equal(result.stderr, "");
    const payload = JSON.parse(result.stdout);
    assert.equal(payload.ok, true);
    assert.equal(payload.data.dryRun, false);
    assert.deepEqual(payload.data.summary.addedControlIds, [secondaryControlId]);
    assert.equal(payload.data.summary.existingControlCount, 1);
    assert.equal(payload.data.summary.nextControlCount, 2);
    assert.deepEqual(payload.data.after.controls.map((control) => control.id).sort(), [primaryControlId, secondaryControlId].sort());
    assert.deepEqual(server.patchBodies, [{ controls: [{ id: primaryControlId }, { id: secondaryControlId }] }]);
    assert.deepEqual(server.requests.map((request) => request.method + " " + request.pathname), [
      `GET /api/v1/risks/${riskId}`,
      `PATCH /api/v1/risks/${riskId}`,
      `GET /api/v1/risks/${riskId}`,
    ]);
    assert.equal(result.stdout.includes(fakeCookie), false);
  } finally {
    await server.close();
    await rm(tempConfigHome, { recursive: true, force: true });
  }
});

async function startRiskServer() {
  const requests = [];
  const patchBodies = [];
  let archived = false;
  let controlIds = [primaryControlId];

  const server = http.createServer(async (request, response) => {
    const url = new URL(request.url || "/", "http://127.0.0.1");
    requests.push({ method: request.method, pathname: url.pathname });

    if (request.method === "GET" && url.pathname === `/api/v1/risks/${riskId}`) {
      writeJson(response, riskFixture({ archived, controlIds }));
      return;
    }

    if (request.method === "DELETE" && url.pathname === `/api/v1/risks/${riskId}`) {
      archived = true;
      writeJson(response, { ok: true });
      return;
    }

    if (request.method === "PATCH" && url.pathname === `/api/v1/risks/${riskId}`) {
      const body = JSON.parse(await readRequestBody(request));
      patchBodies.push(body);
      controlIds = Array.isArray(body.controls) ? body.controls.map((control) => control.id) : controlIds;
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
    patchBodies,
    close: () => new Promise((resolve, reject) => server.close((error) => (error ? reject(error) : resolve()))),
  };
}

function riskFixture({ archived, controlIds }) {
  return {
    id: riskId,
    title: "Synthetic Risk",
    description: "Synthetic risk fixture",
    response: "MITIGATE",
    impact: "MAJOR",
    likelihood: "LIKELY",
    residualImpact: "MAJOR",
    residualLikelihood: "UNLIKELY",
    residualRating: "MEDIUM",
    archivedAt: archived ? "2026-06-18T00:00:00.000Z" : null,
    controls: controlIds.map((id, index) => ({
      id,
      status: "PASSING",
      controlType: { title: `Synthetic Control ${index + 1}` },
    })),
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
