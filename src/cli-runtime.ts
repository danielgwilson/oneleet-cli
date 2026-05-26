import { createRequire } from "node:module";
import { Command } from "commander";
import { resolveConfig, type OneleetConfig } from "./config.js";
import { OneleetApiClient } from "./oneleet-api.js";
import { codeError, fail, makeError, ok, printJson, type CliError } from "./output.js";

export type JsonOptions = { json?: boolean };
export type TenantOptions = JsonOptions & { tenantId?: string };

const AUTH_HELP =
  "No Oneleet session. Log in through Chrome, then run 'oneleet auth import-cdp --port 9333', or set ONELEET_APP_COOKIE and ONELEET_TENANT_ID.";

export function wantsJsonOutput(): boolean {
  return process.argv.includes("--json");
}

export function jsonRequested(opts: JsonOptions = {}): boolean {
  return Boolean(opts.json || wantsJsonOutput());
}

export function getCliVersion(): string {
  try {
    const require = createRequire(import.meta.url);
    const pkg = require("../package.json") as { version?: unknown };
    return typeof pkg.version === "string" ? pkg.version : "0.0.0";
  } catch {
    return "0.0.0";
  }
}

export async function requireConfig(opts: JsonOptions = {}): Promise<OneleetConfig> {
  const config = await resolveConfig();
  if (config.oneleetAppCookie) return config;
  const error = makeError(null, { code: "AUTH_MISSING", message: AUTH_HELP });
  if (jsonRequested(opts)) printJson(fail(error));
  else process.stderr.write(AUTH_HELP + "\n");
  process.exit(2);
}

export function clientFor(config: OneleetConfig): OneleetApiClient {
  return new OneleetApiClient({ config, userAgent: "oneleet-cli/" + getCliVersion() });
}

export function tenantIdFor(opts: TenantOptions, config: OneleetConfig): string {
  const tenantId = opts.tenantId || config.tenantId;
  if (!tenantId) throw codeError("VALIDATION", "No tenant id configured.");
  return tenantId;
}

export function render(value: unknown, opts: JsonOptions = {}): void {
  if (jsonRequested(opts)) printJson(ok(value));
  else printJson(value);
}

export async function runJsonAction(
  action: () => Promise<unknown>,
  opts: JsonOptions = {},
  writeResult?: (result: unknown) => void | Promise<void>,
): Promise<void> {
  try {
    const result = await action();
    if (writeResult) await writeResult(result);
    else render(result, opts);
  } catch (error: any) {
    const cliError = makeError(error);
    if (jsonRequested(opts)) printJson(fail(cliError));
    else process.stderr.write(cliError.code + ": " + cliError.message + "\n");
    process.exitCode = cliError.code === "AUTH_INVALID" || cliError.code === "AUTH_MISSING" ? 2 : 1;
  }
}

export function parsePositiveInteger(value: string, label: string, max = 1000): number {
  if (!/^\d+$/.test(value)) throw codeError("VALIDATION", label + " must be a positive integer.");
  const parsed = Number(value);
  if (!Number.isSafeInteger(parsed) || parsed < 1 || parsed > max) {
    throw codeError("VALIDATION", label + " must be between 1 and " + max + ".");
  }
  return parsed;
}

export function printFailure(error: CliError, opts: JsonOptions = {}, exitCode = 1): void {
  if (jsonRequested(opts)) printJson(fail(error));
  else process.stderr.write(error.code + ": " + error.message + "\n");
  process.exitCode = exitCode;
}

export function parseQueryPairs(pairs: string[] | undefined): Record<string, string> {
  const query: Record<string, string> = {};
  for (const pair of pairs || []) {
    const index = pair.indexOf("=");
    if (index < 1) throw codeError("VALIDATION", 'Invalid query pair "' + pair + '". Use key=value.');
    query[pair.slice(0, index)] = pair.slice(index + 1);
  }
  return query;
}

export function handleParseFailure(error: any): void {
  if (error?.code === "commander.helpDisplayed") {
    process.exitCode = 0;
    return;
  }
  const message =
    String(error?.message || "") === "(outputHelp)"
      ? "Missing subcommand. Run the command group with --help to see available subcommands."
      : error?.message || "Invalid command.";
  if (wantsJsonOutput()) {
    printJson(fail(makeError(codeError("VALIDATION", message))));
    process.exitCode = 1;
    return;
  }
  process.exitCode = typeof error?.exitCode === "number" ? error.exitCode : 1;
}

export function configureParserContract(command: Command): void {
  command
    .configureOutput({
      writeErr: (str) => {
        if (!wantsJsonOutput()) process.stderr.write(str);
      },
    })
    .exitOverride();
  for (const child of command.commands) configureParserContract(child);
}

export function collect(value: string, previous: string[]): string[] {
  previous.push(value);
  return previous;
}
