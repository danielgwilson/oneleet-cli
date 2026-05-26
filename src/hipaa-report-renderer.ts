type CountRow = {
  name?: unknown;
  count?: unknown;
};

type CheckSummary = {
  checksPassingPercentage?: unknown;
  passingChecksCount?: unknown;
  totalChecksCount?: unknown;
};

type ControlSummary = {
  title?: unknown;
  category?: unknown;
  status?: unknown;
  references?: unknown;
  checkSummary?: CheckSummary | null;
  evidenceCount?: unknown;
  evidenceRequestCount?: unknown;
};

type MonitorProblem = {
  status?: unknown;
  monitorType?: unknown;
  controls?: unknown;
  assets?: {
    count?: unknown;
    failingCount?: unknown;
    passingCount?: unknown;
    percentPassing?: unknown;
  };
};

export function renderHipaaReportMarkdown(report: unknown): string {
  const data = asRecord(report);
  const controls = asRecord(data.controls);
  const monitors = asRecord(data.monitors);
  const people = asRecord(data.people);
  const vendors = asRecord(data.vendors);
  const evidence = asRecord(data.evidence);
  const policies = asRecord(data.policies);
  const accessReviews = asRecord(data.accessReviews);
  const domains = asRecord(data.domains);
  const integrations = asRecord(data.integrations);
  const riskAssessments = asRecord(data.riskAssessments);
  const securityTraining = asRecord(data.securityTraining);
  const trustCenter = asRecord(data.trustCenter);
  const reports = asRecord(data.reports);
  const pentests = asRecord(data.pentests);
  const codeSecurity = asRecord(data.codeSecurity);
  const attackSurface = asRecord(data.attackSurface);
  const dashboard = asRecord(data.dashboard);
  const framework = asRecord(data.framework);
  const completeness = asRecord(data.completeness);

  const generatedAt = formatDate(data.generatedAt);
  const totalControls = numberOrNull(controls.total);
  const hipaaMappedTotal = numberOrNull(controls.hipaaMappedTotal);
  const failingControls = asControls(controls.failing);
  const inProgressControls = asControls(controls.inProgress);
  const notStartedControls = asControls(controls.notStarted);
  const unmappedIncludedControls = asControls(controls.unmappedIncluded);
  const problemMonitors = asMonitorProblems(monitors.problems);
  const partialErrors = collectErrors({
    evidence,
    policies,
    accessReviews,
    domains,
    integrations,
    riskAssessments,
    securityTraining,
    trustCenter,
    reports,
    pentests,
    codeSecurity,
    attackSurface,
  });

  const sections: string[] = [];
  sections.push(`# HIPAA Compliance Report`);
  sections.push(`Generated: ${generatedAt}`);
  sections.push(
    `Sanitization: aggregate-only Markdown; person, vendor, tenant, evidence, file, URL, cookie, and email details are omitted.`,
  );
  sections.push(
    table(
      ["Area", "Signal"],
      [
        ["Tenant context", booleanLabel(data.tenantIdConfigured, "Configured", "Not configured")],
        ["Report completeness", booleanLabel(completeness.complete, "Complete", "Incomplete")],
        ["Source errors", formatNumber(Array.isArray(completeness.sourceErrors) ? completeness.sourceErrors.length : null)],
        ["Shape errors", formatNumber(Array.isArray(completeness.shapeErrors) ? completeness.shapeErrors.length : null)],
        ["Pagination gaps", formatNumber(Array.isArray(completeness.paginationGaps) ? completeness.paginationGaps.length : null)],
        ["HIPAA framework", frameworkSignal(framework)],
        ["Controls", countPair(totalControls, hipaaMappedTotal, "total", "HIPAA mapped")],
        ["Controls with linked evidence", formatNumber(controls.withLinkedEvidence)],
        ["Controls with evidence requests", formatNumber(controls.withEvidenceRequests)],
        ["Monitor problems", countPair(numberOrNull(monitors.problemCount), numberOrNull(monitors.total), "problem", "total")],
        ["Evidence inventory", formatNumber(evidence.total)],
        ["Vendor inventory", formatNumber(vendors.total)],
        ["Security training progress rows", formatNumber(securityTraining.userProgressCount)],
        ["Trust center", booleanLabel(trustCenter.published, "Published", "Not published or unknown")],
      ],
    ),
  );

  sections.push(`## Priority Readout`);
  sections.push(
    bulletList([
      priorityLine(failingControls.length, "failing HIPAA-relevant control", "failing HIPAA-relevant controls"),
      priorityLine(inProgressControls.length, "control in progress", "controls in progress"),
      priorityLine(notStartedControls.length, "control not started", "controls not started"),
      priorityLine(problemMonitors.length, "problem monitor", "problem monitors"),
      partialErrors.length > 0
        ? `${partialErrors.length} optional source${partialErrors.length === 1 ? "" : "s"} could not be read completely`
        : "All optional report sources returned without captured CLI errors",
    ]),
  );

  sections.push(`## Control Status`);
  sections.push(
    table(
      ["Status", "Count"],
      countRows(controls.byStatus).map((row) => [humanize(row.name), formatNumber(row.count)]),
      "No control status rows were returned.",
    ),
  );
  sections.push(`## Control Categories`);
  sections.push(
    table(
      ["Category", "Count"],
      countRows(controls.byCategory).map((row) => [humanize(row.name), formatNumber(row.count)]),
      "No control category rows were returned.",
    ),
  );
  sections.push(renderControlsTable("Failing Controls", failingControls));
  sections.push(renderControlsTable("In Progress Controls", inProgressControls));
  sections.push(renderControlsTable("Not Started Controls", notStartedControls));
  if (unmappedIncludedControls.length > 0) {
    sections.push(renderControlsTable("Unmapped Controls Included For HIPAA Readiness", unmappedIncludedControls));
  }

  sections.push(`## Monitor Coverage`);
  sections.push(
    table(
      ["Status", "Count"],
      countRows(monitors.byStatus).map((row) => [humanize(row.name), formatNumber(row.count)]),
      "No monitor status rows were returned.",
    ),
  );
  sections.push(renderMonitorProblems(problemMonitors));

  sections.push(`## People And Training`);
  sections.push(
    table(
      ["Signal", "Value"],
      [
        ["People total", formatNumber(people.total)],
        ["People by status", inlineCounts(people.byStatus)],
        ["People by role", inlineCounts(people.byRole)],
        ["Training modules", formatNumber(securityTraining.moduleCount)],
        ["Training progress by compliance", inlineCounts(securityTraining.progressByCompliance)],
      ],
    ),
  );

  sections.push(`## Vendors And Reviews`);
  sections.push(
    table(
      ["Signal", "Value"],
      [
        ["Vendors total", formatNumber(vendors.total)],
        ["Vendors by status", inlineCounts(vendors.byStatus)],
        ["Vendors using data inventory", formatNumber(vendors.usingDataInventory)],
        ["Vendors with services", formatNumber(vendors.withServices)],
        ["Vendors with processing locations", formatNumber(vendors.withProcessingLocations)],
        ["Vendors with evidence", formatNumber(vendors.withEvidence)],
        ["Access reviews by status", inlineCounts(accessReviews.byStatus)],
        ["Risk assessments by status", inlineCounts(riskAssessments.byStatus)],
      ],
    ),
  );

  sections.push(`## Evidence And Program Inventory`);
  sections.push(
    table(
      ["Signal", "Value"],
      [
        ["Evidence by type", inlineCounts(evidence.byType)],
        ["Evidence by AI review status", inlineCounts(evidence.byAiReviewStatus)],
        ["Evidence attached to controls", formatNumber(evidence.attachedToControls)],
        ["Evidence attached to vendors", formatNumber(evidence.attachedToVendors)],
        ["Policies by status", inlineCounts(policies.byStatus)],
        ["Reports by status", inlineCounts(reports.byStatus)],
        ["Domains by status", inlineCounts(domains.byStatus)],
        ["Integrations by status", inlineCounts(integrations.byStatus)],
        ["Integrations by category", inlineCounts(integrations.byCategory)],
      ],
    ),
  );

  sections.push(`## Trust, Pentest, Code, And Attack Surface`);
  sections.push(
    table(
      ["Signal", "Value"],
      [
        ["Trust center publication", booleanLabel(trustCenter.published, "Published", "Not published or unknown")],
        ["Trust documents", formatNumber(trustCenter.documentCount)],
        ["Trust document requests", formatNumber(trustCenter.documentRequestCount)],
        ["Trust FAQs", formatNumber(trustCenter.faqCount)],
        ["Trust security issues", formatNumber(trustCenter.securityIssueCount)],
        ["Active pentest request", booleanLabel(pentests.hasActiveRequest, "Present", "Not present")],
        ["Code security scan", booleanLabel(codeSecurity.hasScan, "Present", "Not present")],
        ["Code repositories counted", formatNumber(codeSecurity.repositoryCount)],
        ["Attack surface issues returned", countPair(numberOrNull(attackSurface.returnedIssueCount), numberOrNull(attackSurface.totalIssueCount), "returned", "total")],
        ["Attack surface scans returned", countPair(numberOrNull(attackSurface.returnedScanCount), numberOrNull(attackSurface.totalScanCount), "returned", "total")],
      ],
    ),
  );

  sections.push(`## Dashboard Snapshot`);
  sections.push(
    table(
      ["Signal", "Value"],
      [
        ["Completed controls", countPair(numberOrNull(dashboard.completedControlsCount), numberOrNull(dashboard.totalControlsCount), "completed", "total")],
        ["Dashboard people object", presenceLabel(dashboard.people)],
        ["Dashboard vulnerability object", presenceLabel(dashboard.vulnerabilities)],
        ["Dashboard vendor object", presenceLabel(dashboard.vendors)],
      ],
    ),
  );

  if (partialErrors.length > 0) {
    sections.push(`## Partial Source Errors`);
    sections.push(
      table(
        ["Source", "Error code"],
        partialErrors.map((entry) => [humanize(entry.source), sanitizeText(entry.code)]),
      ),
    );
  }

  return `${sections.join("\n\n")}\n`;
}

function renderControlsTable(title: string, controls: ControlSummary[]): string {
  if (controls.length === 0) return `## ${title}\n\nNone reported.`;
  return [
    `## ${title}`,
    table(
      ["Control", "Status", "Category", "References", "Evidence", "Requests", "Checks"],
      controls.map((control) => [
        sanitizeText(control.title),
        humanize(control.status),
        humanize(control.category),
        inlineList(control.references),
        formatNumber(control.evidenceCount),
        formatNumber(control.evidenceRequestCount),
        checkSummary(control.checkSummary),
      ]),
    ),
  ].join("\n\n");
}

function renderMonitorProblems(problems: MonitorProblem[]): string {
  if (problems.length === 0) return `## Problem Monitors\n\nNone reported.`;
  return [
    `## Problem Monitors`,
    table(
      ["Status", "Monitor Type", "Controls", "Assets", "Failing", "Passing Percent"],
      problems.map((problem) => [
        humanize(problem.status),
        sanitizeText(problem.monitorType),
        inlineList(problem.controls),
        formatNumber(problem.assets?.count),
        formatNumber(problem.assets?.failingCount),
        percent(problem.assets?.percentPassing),
      ]),
    ),
  ].join("\n\n");
}

function collectErrors(sections: Record<string, Record<string, unknown>>): Array<{ source: string; code: string }> {
  const errors: Array<{ source: string; code: string }> = [];
  for (const [source, section] of Object.entries(sections)) {
    const error = asRecord(section.error);
    if (Object.keys(error).length === 0) continue;
    errors.push({ source, code: String(error.code || "UNKNOWN") });
  }
  return errors;
}

function table(headers: string[], rows: string[][], emptyMessage = "No rows returned."): string {
  if (rows.length === 0) return emptyMessage;
  return [
    `| ${headers.map(escapeCell).join(" |")} |`,
    `| ${headers.map(() => "---").join(" | ")} |`,
    ...rows.map((row) => `| ${row.map(escapeCell).join(" | ")} |`),
  ].join("\n");
}

function bulletList(items: string[]): string {
  return items.map((item) => `- ${sanitizeText(item)}`).join("\n");
}

function priorityLine(count: number, singular: string, plural: string): string {
  return count === 1 ? `1 ${singular}` : `${count} ${plural}`;
}

function frameworkSignal(framework: Record<string, unknown>): string {
  if (Object.keys(framework).length === 0) return "Unknown";
  const status = framework.status || framework.lifecycle || framework.state;
  const completedControls = framework.completedControlsCount ?? framework.passingControlsCount;
  const progress = countPair(numberOrNull(completedControls), numberOrNull(framework.totalControlsCount), "passing", "total");
  return [status ? humanize(status) : null, progress !== "Unknown" ? progress : null].filter(Boolean).join("; ") || "Present";
}

function inlineCounts(value: unknown): string {
  const rows = countRows(value);
  if (rows.length === 0) return "None reported";
  return rows.map((row) => `${humanize(row.name)}: ${formatNumber(row.count)}`).join(", ");
}

function inlineList(value: unknown): string {
  const rows = Array.isArray(value) ? value : [];
  if (rows.length === 0) return "None";
  return rows.map((item) => sanitizeText(item)).join(", ");
}

function checkSummary(value: unknown): string {
  const summary = asRecord(value) as CheckSummary;
  if (Object.keys(summary).length === 0) return "Unknown";
  const passing = numberOrNull(summary.passingChecksCount);
  const total = numberOrNull(summary.totalChecksCount);
  const percentage = percent(summary.checksPassingPercentage);
  const counts = countPair(passing, total, "passing", "total");
  return percentage === "Unknown" ? counts : `${counts}; ${percentage}`;
}

function countPair(first: number | null, second: number | null, firstLabel: string, secondLabel: string): string {
  if (first == null && second == null) return "Unknown";
  if (second == null) return `${formatNumber(first)} ${firstLabel}`;
  if (first == null) return `${formatNumber(second)} ${secondLabel}`;
  return `${formatNumber(first)} ${firstLabel} / ${formatNumber(second)} ${secondLabel}`;
}

function countRows(value: unknown): CountRow[] {
  if (!Array.isArray(value)) return [];
  return value.map((row) => asRecord(row) as CountRow);
}

function asControls(value: unknown): ControlSummary[] {
  if (!Array.isArray(value)) return [];
  return value.map((row) => asRecord(row) as ControlSummary);
}

function asMonitorProblems(value: unknown): MonitorProblem[] {
  if (!Array.isArray(value)) return [];
  return value.map((row) => asRecord(row) as MonitorProblem);
}

function asRecord(value: unknown): Record<string, unknown> {
  return value && typeof value === "object" && !Array.isArray(value) ? (value as Record<string, unknown>) : {};
}

function formatDate(value: unknown): string {
  if (typeof value !== "string") return "Unknown";
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return sanitizeText(value);
  return date.toISOString();
}

function formatNumber(value: unknown): string {
  const number = numberOrNull(value);
  return number == null ? "Unknown" : new Intl.NumberFormat("en-US").format(number);
}

function numberOrNull(value: unknown): number | null {
  if (typeof value === "number" && Number.isFinite(value)) return value;
  if (typeof value === "string" && value.trim() !== "") {
    const number = Number(value);
    if (Number.isFinite(number)) return number;
  }
  return null;
}

function percent(value: unknown): string {
  const number = numberOrNull(value);
  if (number == null) return "Unknown";
  const normalized = number > 0 && number <= 1 ? number * 100 : number;
  return `${normalized.toFixed(normalized % 1 === 0 ? 0 : 1)}%`;
}

function booleanLabel(value: unknown, trueLabel: string, falseLabel: string): string {
  return value === true ? trueLabel : falseLabel;
}

function presenceLabel(value: unknown): string {
  return Object.keys(asRecord(value)).length > 0 ? "Present" : "Not returned";
}

function humanize(value: unknown): string {
  const text = sanitizeText(value);
  if (text === "Unknown") return text;
  return text
    .replace(/([a-z0-9])([A-Z])/g, "$1 $2")
    .replace(/[_-]+/g, " ")
    .replace(/\s+/g, " ")
    .trim()
    .toLowerCase()
    .replace(/\b[a-z]/g, (letter) => letter.toUpperCase());
}

function sanitizeText(value: unknown): string {
  if (value == null) return "Unknown";
  const text = String(value).trim();
  if (!text) return "Unknown";
  return text
    .replace(/\boneleet-app=([^;\s]+)/gi, "oneleet-app=[redacted]")
    .replace(/[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}/gi, "[redacted-email]")
    .replace(/\bhttps?:\/\/\S+/gi, "[redacted-url]")
    .replace(/\b[A-Fa-f0-9]{8}-[A-Fa-f0-9]{4}-[1-5][A-Fa-f0-9]{3}-[89ABab][A-Fa-f0-9]{3}-[A-Fa-f0-9]{12}\b/g, "[redacted-id]")
    .replace(/\b[\w .-]+\.(?:pdf|docx?|xlsx?|csv|tsv|png|jpe?g|gif|webp|zip|tar|gz|json|har)\b/gi, "[redacted-file]");
}

function escapeCell(value: string): string {
  return sanitizeText(value).replace(/\|/g, "\\|").replace(/\n+/g, " ");
}
