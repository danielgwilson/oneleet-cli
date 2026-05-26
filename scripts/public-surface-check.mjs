#!/usr/bin/env node
import { execFileSync } from "node:child_process";
import { readFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const pack = JSON.parse(execFileSync("npm", ["pack", "--dry-run", "--json", "--silent"], { cwd: root, encoding: "utf8" }));
const files = pack[0]?.files || [];
const failures = [];
const packagedPaths = new Set(files.map((file) => file.path));

const requiredPackagedPaths = [
  "LICENSE",
  "README.md",
  "CONTRIBUTING.md",
  "SECURITY.md",
  "SKILL.md",
  "dist/cli.js",
  "docs/CONTRACT_V1.md",
  "docs/COVERAGE.md",
  "docs/PUBLISHING.md",
  "skills/oneleet/SKILL.md",
  "package.json",
];

const forbiddenPathPatterns = [
  /(^|\/)node_modules\//,
  /(^|\/)tests?\//,
  /(^|\/)scripts?\//,
  /(^|\/)\.env/i,
  /\.(har|trace|zip|png|jpe?g|webp|pdf|docx?|xlsx?|csv|tsv)$/i,
  /storage[-_]?state/i,
  /cookie/i,
];

const forbiddenPackagedRoots = ["src/", "tests/", "scripts/", "node_modules/"];

const forbiddenContentPatterns = [
  { name: "live oneleet-app cookie", pattern: /oneleet-app=(?!\[redacted\]|\$\{)[A-Za-z0-9._~+/=-]{16,}/ },
  { name: "customer tenant uuid", pattern: /100ae028-2525-4687-aff8-5d3208b2dc45/i },
  { name: "email address", pattern: /[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}/i },
  { name: "local absolute path", pattern: /\/Users\/danielgwilson\// },
  { name: "network capture marker", pattern: /\b(storageState|trace\.zip|\.har)\b/i },
];

for (const requiredPath of requiredPackagedPaths) {
  if (!packagedPaths.has(requiredPath)) failures.push(`${requiredPath}: required packaged file missing`);
}

const cliEntry = files.find((file) => file.path === "dist/cli.js");
if (cliEntry && cliEntry.mode !== 0o755) {
  failures.push("dist/cli.js: expected executable mode 755");
}

for (const file of files) {
  const relativePath = file.path;
  if (forbiddenPackagedRoots.some((rootPath) => relativePath.startsWith(rootPath))) {
    failures.push(`${relativePath}: forbidden packaged root`);
  }

  for (const pattern of forbiddenPathPatterns) {
    if (pattern.test(relativePath)) failures.push(`${relativePath}: forbidden packaged path`);
  }

  const absolutePath = path.join(root, relativePath);
  let content = "";
  try {
    content = readFileSync(absolutePath, "utf8");
  } catch {
    continue;
  }

  for (const { name, pattern } of forbiddenContentPatterns) {
    if (pattern.test(content)) failures.push(`${relativePath}: ${name}`);
  }
}

if (failures.length > 0) {
  console.error(failures.join("\n"));
  process.exit(1);
}

console.log(`Public surface check passed (${files.length} packaged files).`);
