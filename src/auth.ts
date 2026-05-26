import CDP from "chrome-remote-interface";
import { writeConfig, type OneleetConfig } from "./config.js";
import { OneleetApiClient } from "./oneleet-api.js";

export type ValidationResult = {
  ok: boolean;
  reason?: string;
  errorCode?: string;
  sample?: {
    currentUserOk: boolean;
    tenantOk: boolean;
    dashboardOk: boolean;
  };
};

export async function validateConfig(config: OneleetConfig): Promise<ValidationResult> {
  if (!config.oneleetAppCookie) return { ok: false, reason: "Missing oneleet-app cookie", errorCode: "AUTH_MISSING" };
  if (!config.tenantId) return { ok: false, reason: "Missing tenant id", errorCode: "AUTH_MISSING" };

  try {
    const client = new OneleetApiClient({ config });
    await client.getCurrentUser();
    await client.getTenant();
    await client.getDashboard();
    return { ok: true, sample: { currentUserOk: true, tenantOk: true, dashboardOk: true } };
  } catch (error: any) {
    const status = error?.status;
    const errorCode = typeof error?.code === "string" ? error.code : status === 401 || status === 403 ? "AUTH_INVALID" : "CHECK_FAILED";
    return { ok: false, reason: error?.message || "Validation failed", errorCode };
  }
}

export async function saveAndValidate(config: OneleetConfig): Promise<{ config: OneleetConfig; validation: ValidationResult; saved: boolean }> {
  const validation = await validateConfig(config);
  if (validation.ok) {
    await writeConfig(config);
    return { config, validation, saved: true };
  }
  return { config, validation, saved: false };
}

export async function importFromCdp({ port = 9333, host = "127.0.0.1" }: { port?: number; host?: string }): Promise<OneleetConfig> {
  const targets = await CDP.List({ host, port });
  const target = targets.find((candidate: any) => candidate.type === "page" && String(candidate.url || "").includes("app.oneleet.com"));
  if (!target) throw new Error("No app.oneleet.com Chrome page target available via CDP");

  const client = await CDP({ host, port, target });
  try {
    const { Network, Runtime } = client;
    await Promise.all([Network.enable(), Runtime.enable()]);

    const current = await Runtime.evaluate({
      expression: "JSON.stringify({ href: location.href, title: document.title })",
      returnByValue: true,
    });
    const pageInfo = JSON.parse(current.result?.value || "{}") as { href?: string };
    const tenantId = extractTenantId(pageInfo.href || target.url || "");

    const cookiesResult = await Network.getCookies({
      urls: ["https://app.oneleet.com", "https://api.oneleet.com", "https://auth.oneleet.com"],
    });
    const oneleetApp = (cookiesResult.cookies || []).find((cookie: any) => cookie.name === "oneleet-app");
    if (!oneleetApp?.value) throw new Error("Could not find oneleet-app cookie in the attached Chrome session");

    return {
      oneleetAppCookie: oneleetApp.value,
      tenantId,
      appBaseUrl: "https://app.oneleet.com",
      apiBaseUrl: "https://api.oneleet.com",
    };
  } finally {
    await client.close();
  }
}

function extractTenantId(url: string): string {
  const match = url.match(/\/tenants\/([0-9a-f-]{36})(?:\/|$|\?)/i);
  return match?.[1] || "";
}
