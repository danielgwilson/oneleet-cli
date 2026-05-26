import { codeError } from "./output.js";

export function assertSafeAggregateReport(report: unknown, label = "Aggregate report"): void {
  const serialized = JSON.stringify(report);
  const unsafePatterns = [
    { name: "email address", pattern: /[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}/i },
    { name: "URL", pattern: /https?:\/\//i },
    { name: "session cookie", pattern: /oneleet-app=/i },
    { name: "session cookie env", pattern: /ONELEET_APP_COOKIE=/i },
    { name: "session cookie json", pattern: /oneleetAppCookie/i },
    { name: "UUID/internal ID", pattern: /\b[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}\b/i },
    { name: "local absolute path", pattern: /\/Users\/[A-Za-z0-9._-]+\// },
    { name: "file-like name", pattern: /\b[A-Za-z0-9][A-Za-z0-9_. -]*\.(?:csv|tsv|xlsx?|docx?|pdf|png|jpe?g|webp|har|zip)\b/i },
  ];
  const match = unsafePatterns.find(({ pattern }) => pattern.test(serialized));
  if (match) throw codeError("CHECK_FAILED", `${label} failed safety gate: ${match.name} detected.`);
}

function safeRowRef(prefix: string, index: number): string {
  return `${prefix}-${String(index + 1).padStart(3, "0")}`;
}

export function safeRowMeta(prefix: string, index: number, row: any): Record<string, unknown> {
  return { ref: safeRowRef(prefix, index), hasId: Boolean(row?.id) };
}
