import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";

export type OneleetConfig = {
  oneleetAppCookie?: string;
  tenantId?: string;
  appBaseUrl?: string;
  apiBaseUrl?: string;
  allowUnsafeApiBaseUrl?: boolean;
};

export type ResolvedConfig = OneleetConfig & {
  source: "env" | "config" | "mixed" | "none";
};

export const DEFAULT_APP_BASE_URL = "https://app.oneleet.com";
export const DEFAULT_API_BASE_URL = "https://api.oneleet.com";

function getConfigDir(): string {
  const xdg = process.env.XDG_CONFIG_HOME?.trim();
  return xdg || path.join(os.homedir(), ".config");
}

export function getConfigPath(): string {
  return path.join(getConfigDir(), "oneleet", "config.json");
}

export function getDisplayConfigPath(): string {
  const xdg = process.env.XDG_CONFIG_HOME?.trim();
  if (xdg) return "$XDG_CONFIG_HOME/oneleet/config.json";
  return "~/.config/oneleet/config.json";
}

export async function readConfig(): Promise<OneleetConfig> {
  try {
    const raw = await fs.readFile(getConfigPath(), "utf8");
    const parsed = JSON.parse(raw);
    return parsed && typeof parsed === "object" ? (parsed as OneleetConfig) : {};
  } catch {
    return {};
  }
}

export async function writeConfig(config: OneleetConfig): Promise<void> {
  const configPath = getConfigPath();
  await fs.mkdir(path.dirname(configPath), { recursive: true });
  await fs.writeFile(configPath, JSON.stringify(config, null, 2), { mode: 0o600 });
  try {
    await fs.chmod(configPath, 0o600);
  } catch {
    // Best effort on non-POSIX filesystems.
  }
}

export async function clearConfig(): Promise<void> {
  try {
    await fs.unlink(getConfigPath());
  } catch {
    // ignore
  }
}

export async function resolveConfig(): Promise<ResolvedConfig> {
  const fileConfig = await readConfig();
  const envCookie = process.env.ONELEET_APP_COOKIE?.trim();
  const envTenantId = process.env.ONELEET_TENANT_ID?.trim();
  const envAppBaseUrl = process.env.ONELEET_APP_BASE_URL?.trim();
  const envApiBaseUrl = process.env.ONELEET_API_BASE_URL?.trim();
  const envAllowUnsafeApiBaseUrl = process.env.ONELEET_ALLOW_UNSAFE_API_BASE_URL?.trim();

  const config: OneleetConfig = {
    oneleetAppCookie: envCookie || fileConfig.oneleetAppCookie,
    tenantId: envTenantId || fileConfig.tenantId,
    appBaseUrl: stripTrailingSlash(envAppBaseUrl || fileConfig.appBaseUrl || DEFAULT_APP_BASE_URL),
    apiBaseUrl: stripTrailingSlash(envApiBaseUrl || fileConfig.apiBaseUrl || DEFAULT_API_BASE_URL),
    allowUnsafeApiBaseUrl: envAllowUnsafeApiBaseUrl === "1" || envAllowUnsafeApiBaseUrl === "true",
  };

  const fromEnv = Boolean(envCookie || envTenantId || envAppBaseUrl || envApiBaseUrl || envAllowUnsafeApiBaseUrl);
  const fromConfig = Boolean(fileConfig.oneleetAppCookie || fileConfig.tenantId || fileConfig.appBaseUrl || fileConfig.apiBaseUrl);
  const source: ResolvedConfig["source"] = fromEnv && fromConfig ? "mixed" : fromEnv ? "env" : fromConfig ? "config" : "none";

  return { ...config, source };
}

export function redactCookie(value: string | undefined): string | null {
  if (!value) return null;
  if (value.length <= 12) return `${value.slice(0, 4)}...`;
  return `${value.slice(0, 6)}...${value.slice(-4)}`;
}

export function stripTrailingSlash(value: string): string {
  return value.replace(/\/+$/, "");
}
