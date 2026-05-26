import { makeError } from "./output.js";

export function rowsOf(value: any): any[] {
  if (Array.isArray(value)) return value;
  if (Array.isArray(value?.rows)) return value.rows;
  return [];
}

export function hasListShape(value: any): boolean {
  if (errorOf(value)) return true;
  if (value == null) return true;
  if (Array.isArray(value)) return true;
  if (!value || typeof value !== "object") return false;
  if (!("rows" in value)) return false;
  return value.rows == null || Array.isArray(value.rows);
}

export function countBy<T>(rows: T[], keyFn: (row: T) => string): Array<{ name: string; count: number }> {
  const counts = new Map<string, number>();
  for (const row of rows) {
    const key = keyFn(row) || "UNKNOWN";
    counts.set(key, (counts.get(key) || 0) + 1);
  }
  return Array.from(counts.entries())
    .sort((a, b) => a[0].localeCompare(b[0]))
    .map(([name, count]) => ({ name, count }));
}

export function isHipaaControl(row: any): boolean {
  return Array.isArray(row?.tenantComplianceRequirements)
    ? row.tenantComplianceRequirements.some((req: any) => String(req?.frameworkName || "").toUpperCase() === "HIPAA")
    : false;
}

export function isHipaaRelevantControl(row: any): boolean {
  if (isHipaaControl(row)) return true;
  return row?.category === "VULNERABILITY_MANAGEMENT" && row?.title === "Vulnerabilities remediated";
}

export function summarizeControl(row: any): Record<string, unknown> {
  return {
    title: row.title,
    category: row.category,
    status: row.status,
    references: Array.isArray(row.tenantComplianceRequirements)
      ? row.tenantComplianceRequirements
          .filter((req: any) => String(req?.frameworkName || "").toUpperCase() === "HIPAA")
          .map((req: any) => req.referenceId)
          .filter(Boolean)
      : [],
    checkSummary: summarizeCheckSummary(row.checkSummary),
    evidenceCount: Array.isArray(row.evidence) ? row.evidence.length : 0,
    evidenceRequestCount: Array.isArray(row.evidenceRequests) ? row.evidenceRequests.length : 0,
  };
}

export function summarizeCheckSummary(checkSummary: any): unknown {
  if (!checkSummary || typeof checkSummary !== "object") return checkSummary || null;
  return {
    allActiveChecksArePassing: checkSummary.allActiveChecksArePassing ?? null,
    checksPassingPercentage: checkSummary.checksPassingPercentage ?? null,
    enabledChecksCount: checkSummary.enabledChecksCount ?? null,
    hasChecks: checkSummary.hasChecks ?? null,
    inactiveChecksCount: checkSummary.inactiveChecksCount ?? null,
    passingChecksCount: checkSummary.passingChecksCount ?? null,
    totalChecksCount: checkSummary.totalChecksCount ?? null,
  };
}

export function statusOf(row: any): string {
  if (typeof row?.status === "string" && row.status) return row.status;
  if (typeof row?.lifecycle === "string" && row.lifecycle) return row.lifecycle;
  if (typeof row?.state === "string" && row.state) return row.state;
  if (typeof row?.isVerified === "boolean") return row.isVerified ? "VERIFIED" : "UNVERIFIED";
  if (typeof row?.isCompliant === "boolean") return row.isCompliant ? "COMPLIANT" : "NON_COMPLIANT";
  if (typeof row?.isCompleted === "boolean") return row.isCompleted ? "COMPLETED" : "NOT_COMPLETED";
  return "UNKNOWN";
}

export function integrationStatus(row: any): string {
  if (!Array.isArray(row?.connections) || row.connections.length === 0) return statusOf(row);
  const statuses = row.connections.map((connection: any) => connection.status).filter(Boolean);
  if (statuses.length === 0) return "UNKNOWN";
  if (statuses.some((status: string) => status === "FAILED")) return "FAILED";
  if (statuses.every((status: string) => status === "SUCCEEDED" || status === "CONNECTED")) return "CONNECTED";
  return statuses[0] || "UNKNOWN";
}

export async function optionalRead<T>(read: Promise<T>): Promise<T | { error: ReturnType<typeof makeError> }> {
  try {
    return await read;
  } catch (error: any) {
    return { error: makeError(error) };
  }
}

export function errorOf(value: any): ReturnType<typeof makeError> | null {
  return value && typeof value === "object" && value.error ? value.error : null;
}

export function sourceError(source: string, value: any): Record<string, unknown> | null {
  const error = errorOf(value);
  if (!error) return null;
  return { source, code: error.code, retryable: error.retryable };
}

export function shapeError(source: string, value: any): Record<string, unknown> | null {
  if (hasListShape(value)) return null;
  return { source, code: "SHAPE_MISMATCH" };
}

export function keyedArrayShapeError(source: string, value: any, key: string): Record<string, unknown> | null {
  if (errorOf(value)) return null;
  if (!value || typeof value !== "object" || !Array.isArray(value[key])) return { source, code: "SHAPE_MISMATCH" };
  return null;
}

export function paginationGap(source: string, rows: any, pagination: any): Record<string, unknown> | null {
  if (!Array.isArray(rows) || !pagination || typeof pagination !== "object") return null;
  const total = typeof pagination.total === "number" ? pagination.total : null;
  if (total == null || rows.length >= total) return null;
  return { source, returned: rows.length, total };
}

export function rowsPaginationGap(source: string, value: any): Record<string, unknown> | null {
  if (errorOf(value)) return null;
  return paginationGap(source, rowsOf(value), value?.pagination);
}

export function listCompleteness(sources: Record<string, unknown>): Record<string, unknown> {
  const entries = Object.entries(sources);
  const sourceErrors = entries.map(([source, value]) => sourceError(source, value)).filter(Boolean);
  const shapeErrors = entries.map(([source, value]) => shapeError(source, value)).filter(Boolean);
  const paginationGaps = entries.map(([source, value]) => rowsPaginationGap(source, value)).filter(Boolean);
  return {
    complete: sourceErrors.length === 0 && shapeErrors.length === 0 && paginationGaps.length === 0,
    sourceErrors,
    shapeErrors,
    paginationGaps,
  };
}

export function keyedCompleteness(sources: Record<string, { value: unknown; key: string }>): Record<string, unknown> {
  const entries = Object.entries(sources);
  const sourceErrors = entries.map(([source, { value }]) => sourceError(source, value)).filter(Boolean);
  const shapeErrors = entries.map(([source, { value, key }]) => keyedArrayShapeError(source, value, key)).filter(Boolean);
  const paginationGaps = entries.map(([source, { value, key }]) => paginationGap(source, (value as any)?.[key], (value as any)?.pagination)).filter(Boolean);
  return {
    complete: sourceErrors.length === 0 && shapeErrors.length === 0 && paginationGaps.length === 0,
    sourceErrors,
    shapeErrors,
    paginationGaps,
  };
}

export function mergeCompleteness(...items: Array<Record<string, any>>): Record<string, unknown> {
  const sourceErrors = items.flatMap((item) => (Array.isArray(item.sourceErrors) ? item.sourceErrors : []));
  const shapeErrors = items.flatMap((item) => (Array.isArray(item.shapeErrors) ? item.shapeErrors : []));
  const paginationGaps = items.flatMap((item) => (Array.isArray(item.paginationGaps) ? item.paginationGaps : []));
  return {
    complete: sourceErrors.length === 0 && shapeErrors.length === 0 && paginationGaps.length === 0,
    sourceErrors,
    shapeErrors,
    paginationGaps,
  };
}

export function countWhere<T>(rows: T[], predicate: (row: T) => boolean): number {
  return rows.filter(predicate).length;
}

export function boolCount<T>(rows: T[], key: (row: T) => boolean): Record<string, number> {
  return {
    true: rows.filter(key).length,
    false: rows.filter((row) => !key(row)).length,
  };
}

export function openAttackIssues(raw: any): any[] {
  return Array.isArray(raw?.issues) ? raw.issues.filter((issue: any) => statusOf(issue) !== "RESOLVED") : [];
}

export function sourceStatus(source: string, value: any, kind: "list" | "object" | "keyed-list", key?: string): Record<string, unknown> {
  const error = errorOf(value);
  if (error) return { source, ok: false, kind, code: error.code, retryable: error.retryable };
  if (kind === "keyed-list") {
    const rows = key && Array.isArray(value?.[key]) ? value[key] : [];
    return {
      source,
      ok: Boolean(key && value && typeof value === "object" && Array.isArray(value[key])),
      kind,
      rowCount: rows.length,
      total: value?.pagination?.total ?? null,
    };
  }
  if (kind === "list") {
    const shaped = hasListShape(value);
    return { source, ok: shaped, kind, rowCount: rowsOf(value).length, total: value?.pagination?.total ?? null };
  }
  return { source, ok: value !== undefined && !error, kind, present: value != null };
}

export function compactProblemMonitor(row: any): Record<string, unknown> {
  return {
    status: row.status,
    monitorType: row.monitorType?.name || null,
    controls: Array.isArray(row.controlSummaries) ? row.controlSummaries.map((control: any) => control.title).filter(Boolean) : [],
    assets: {
      count: row.stats?.assets?.count ?? null,
      failingCount: row.stats?.assets?.failingCount ?? null,
      passingCount: row.stats?.assets?.passingCount ?? null,
      percentPassing: row.stats?.assets?.percentPassing ?? null,
    },
  };
}
