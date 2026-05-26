import { writeFile } from "node:fs/promises";
import { OneleetApiClient } from "./oneleet-api.js";
import { renderHipaaReportMarkdown } from "./hipaa-report-renderer.js";
import { codeError, ok, printJson } from "./output.js";
import { assertSafeAggregateReport } from "./safety.js";
import { jsonRequested, render, type TenantOptions } from "./cli-runtime.js";
import {
  compactProblemMonitor,
  countBy,
  errorOf,
  integrationStatus,
  isHipaaControl,
  isHipaaRelevantControl,
  keyedArrayShapeError,
  optionalRead,
  paginationGap,
  rowsOf,
  rowsPaginationGap,
  shapeError,
  sourceError,
  statusOf,
  summarizeControl,
} from "./report-helpers.js";
import { summarizeFrameworkStats } from "./summaries.js";

export type HipaaReportFormat = "json" | "markdown";
export type HipaaReportOptions = TenantOptions & { format?: string; out?: string };

function parseHipaaReportFormat(value: string | undefined): HipaaReportFormat {
  const normalized = (value || "json").toLowerCase();
  if (normalized === "json") return "json";
  if (normalized === "markdown" || normalized === "md") return "markdown";
  throw codeError("VALIDATION", "Unsupported HIPAA report format. Use json or markdown.");
}

export async function writeHipaaReportOutput(report: unknown, opts: HipaaReportOptions): Promise<void> {
  assertSafeAggregateReport(report, "HIPAA report");
  const format = parseHipaaReportFormat(opts.format);
  if (format === "json") {
    if (opts.out) throw codeError("VALIDATION", "--out is only supported with --format markdown.");
    render(report, opts);
    return;
  }

  const markdown = renderHipaaReportMarkdown(report);
  if (opts.out) {
    try {
      await writeFile(opts.out, markdown, "utf8");
    } catch {
      throw new Error("Could not write HIPAA Markdown report.");
    }
    if (jsonRequested(opts)) printJson(ok({ format: "markdown", written: true }));
    else process.stdout.write("Wrote HIPAA Markdown report.\n");
    return;
  }

  if (jsonRequested(opts)) printJson(ok({ format: "markdown", markdown }));
  else process.stdout.write(markdown.endsWith("\n") ? markdown : markdown + "\n");
}

export async function buildHipaaReport(client: OneleetApiClient, tenantId: string | undefined): Promise<Record<string, unknown>> {
  const [
    dashboard,
    controlsRaw,
    monitorsRaw,
    peopleRaw,
    vendorsRaw,
    evidenceRaw,
    policiesRaw,
    frameworksRaw,
    accessReviewsRaw,
    domainsRaw,
    integrationsRaw,
    riskAssessmentsRaw,
    trainingModulesRaw,
    trainingProgressRaw,
    trustConfigRaw,
    trustDocumentsRaw,
    trustDocumentRequestsRaw,
    trustFaqsRaw,
    trustSecurityIssuesRaw,
    reportsRaw,
    pentestActiveRaw,
    codeScanRaw,
    codeSettingsRaw,
    gitRepositoriesRaw,
    attackStats,
    attackIssues,
    attackScans,
  ] = await Promise.all([
    client.getDashboard(tenantId),
    client.listControls(tenantId),
    client.listMonitors(tenantId),
    client.listMembers(tenantId),
    client.listVendors(tenantId),
    optionalRead(client.listEvidence(tenantId)),
    optionalRead(client.listPolicies(tenantId)),
    optionalRead(client.listFrameworks(tenantId)),
    optionalRead(client.listAccessReviews(tenantId)),
    optionalRead(client.listDomains(tenantId)),
    optionalRead(client.listIntegrations(tenantId)),
    optionalRead(client.listRiskAssessments(tenantId)),
    optionalRead(client.listSecurityTrainingModules(tenantId)),
    optionalRead(client.listSecurityTrainingProgress(tenantId)),
    optionalRead(client.getTrustConfig(tenantId)),
    optionalRead(client.listTrustDocuments(tenantId)),
    optionalRead(client.listTrustDocumentRequests(tenantId)),
    optionalRead(client.listTrustFaqs(tenantId)),
    optionalRead(client.listTrustSecurityIssues(tenantId)),
    optionalRead(client.listReports(tenantId)),
    optionalRead(client.getActivePentestRequest(tenantId)),
    optionalRead(client.getCodeSecurityScan(tenantId)),
    optionalRead(client.getCodeSecuritySettings(tenantId)),
    optionalRead(client.listGitRepositories(tenantId)),
    optionalRead(client.getAttackSurfaceStats(tenantId)),
    optionalRead(client.listAttackSurfaceIssues(tenantId, { limit: 1000 })),
    optionalRead(client.listAttackSurfaceScans(tenantId, { limit: 1000 })),
  ]);
  const controls = rowsOf(controlsRaw).filter(isHipaaControl);
  const relevantControls = rowsOf(controlsRaw).filter(isHipaaRelevantControl);
  const unmappedIncludedControls = relevantControls.filter((row) => !isHipaaControl(row)).map(summarizeControl);
  const failingControls = relevantControls.filter((row) => row.status === "FAILING").map(summarizeControl);
  const inProgressControls = relevantControls.filter((row) => row.status === "IN_PROGRESS").map(summarizeControl);
  const notStartedControls = relevantControls.filter((row) => row.status === "NOT_STARTED").map(summarizeControl);
  const monitors = rowsOf(monitorsRaw);
  const problemMonitors = monitors.filter((row: any) => row.status === "ALERTING" || row.status === "BREACHING_SLA");
  const members = rowsOf(peopleRaw);
  const vendors = rowsOf(vendorsRaw);
  const evidence = rowsOf(evidenceRaw);
  const policies = rowsOf(policiesRaw);
  const frameworks = rowsOf(frameworksRaw);
  const accessReviews = rowsOf(accessReviewsRaw);
  const domains = rowsOf(domainsRaw);
  const integrations = rowsOf(integrationsRaw);
  const riskAssessments = rowsOf(riskAssessmentsRaw);
  const trainingModules = rowsOf(trainingModulesRaw);
  const trainingProgress = rowsOf(trainingProgressRaw);
  const trustDocuments = rowsOf(trustDocumentsRaw);
  const trustDocumentRequests = rowsOf(trustDocumentRequestsRaw);
  const trustFaqs = rowsOf(trustFaqsRaw);
  const trustSecurityIssues = rowsOf(trustSecurityIssuesRaw);
  const reports = rowsOf(reportsRaw);
  const gitRepositories = rowsOf(gitRepositoriesRaw);
  const frameworkStats = rowsOf((dashboard as any)?.data?.dashboardStats?.frameworks).find(
    (framework: any) => String(framework.name || "").toUpperCase() === "HIPAA",
  );
  const dashboardStats = (dashboard as any)?.data?.dashboardStats || {};
  const sourceErrors = [
    sourceError("evidence", evidenceRaw),
    sourceError("policies", policiesRaw),
    sourceError("frameworks", frameworksRaw),
    sourceError("accessReviews", accessReviewsRaw),
    sourceError("domains", domainsRaw),
    sourceError("integrations", integrationsRaw),
    sourceError("riskAssessments", riskAssessmentsRaw),
    sourceError("securityTrainingModules", trainingModulesRaw),
    sourceError("securityTrainingProgress", trainingProgressRaw),
    sourceError("trustConfig", trustConfigRaw),
    sourceError("trustDocuments", trustDocumentsRaw),
    sourceError("trustDocumentRequests", trustDocumentRequestsRaw),
    sourceError("trustFaqs", trustFaqsRaw),
    sourceError("trustSecurityIssues", trustSecurityIssuesRaw),
    sourceError("reports", reportsRaw),
    sourceError("pentestActiveRequest", pentestActiveRaw),
    sourceError("codeSecurityScan", codeScanRaw),
    sourceError("codeSecuritySettings", codeSettingsRaw),
    sourceError("gitRepositories", gitRepositoriesRaw),
    sourceError("attackSurfaceStats", attackStats),
    sourceError("attackSurfaceIssues", attackIssues),
    sourceError("attackSurfaceScans", attackScans),
  ].filter(Boolean);
  const shapeErrors = [
    shapeError("controls", controlsRaw),
    shapeError("monitors", monitorsRaw),
    shapeError("people", peopleRaw),
    shapeError("vendors", vendorsRaw),
    shapeError("evidence", evidenceRaw),
    shapeError("policies", policiesRaw),
    shapeError("frameworks", frameworksRaw),
    shapeError("accessReviews", accessReviewsRaw),
    shapeError("domains", domainsRaw),
    shapeError("integrations", integrationsRaw),
    shapeError("riskAssessments", riskAssessmentsRaw),
    shapeError("securityTrainingModules", trainingModulesRaw),
    shapeError("securityTrainingProgress", trainingProgressRaw),
    shapeError("trustDocuments", trustDocumentsRaw),
    shapeError("trustDocumentRequests", trustDocumentRequestsRaw),
    shapeError("trustFaqs", trustFaqsRaw),
    shapeError("trustSecurityIssues", trustSecurityIssuesRaw),
    shapeError("reports", reportsRaw),
    shapeError("gitRepositories", gitRepositoriesRaw),
    keyedArrayShapeError("attackSurfaceIssues", attackIssues, "issues"),
    keyedArrayShapeError("attackSurfaceScans", attackScans, "scans"),
  ].filter(Boolean);
  const paginationGaps = [
    rowsPaginationGap("controls", controlsRaw),
    rowsPaginationGap("monitors", monitorsRaw),
    rowsPaginationGap("people", peopleRaw),
    rowsPaginationGap("vendors", vendorsRaw),
    rowsPaginationGap("evidence", evidenceRaw),
    rowsPaginationGap("policies", policiesRaw),
    rowsPaginationGap("frameworks", frameworksRaw),
    rowsPaginationGap("accessReviews", accessReviewsRaw),
    rowsPaginationGap("domains", domainsRaw),
    rowsPaginationGap("integrations", integrationsRaw),
    rowsPaginationGap("riskAssessments", riskAssessmentsRaw),
    rowsPaginationGap("securityTrainingModules", trainingModulesRaw),
    rowsPaginationGap("securityTrainingProgress", trainingProgressRaw),
    rowsPaginationGap("trustDocuments", trustDocumentsRaw),
    rowsPaginationGap("trustDocumentRequests", trustDocumentRequestsRaw),
    rowsPaginationGap("trustFaqs", trustFaqsRaw),
    rowsPaginationGap("trustSecurityIssues", trustSecurityIssuesRaw),
    rowsPaginationGap("reports", reportsRaw),
    rowsPaginationGap("gitRepositories", gitRepositoriesRaw),
    paginationGap("attackSurfaceIssues", (attackIssues as any)?.issues, (attackIssues as any)?.pagination),
    paginationGap("attackSurfaceScans", (attackScans as any)?.scans, (attackScans as any)?.pagination),
  ].filter(Boolean);

  return {
    generatedAt: new Date().toISOString(),
    tenantIdConfigured: Boolean(tenantId),
    completeness: {
      complete: sourceErrors.length === 0 && shapeErrors.length === 0 && paginationGaps.length === 0,
      sourceErrors,
      shapeErrors,
      paginationGaps,
    },
    framework: summarizeFrameworkStats(frameworkStats),
    dashboard: {
      people: dashboardStats.people || null,
      vulnerabilities: dashboardStats.vulnerabilities || null,
      vendors: dashboardStats.vendors || null,
      completedControlsCount: (dashboard as any)?.data?.completedControlsCount ?? null,
      totalControlsCount: (dashboard as any)?.data?.totalControlsCount ?? null,
    },
    controls: {
      total: relevantControls.length,
      hipaaMappedTotal: controls.length,
      unmappedIncluded: unmappedIncludedControls,
      byStatus: countBy(relevantControls, (row: any) => row.status),
      byCategory: countBy(relevantControls, (row: any) => row.category),
      withLinkedEvidence: relevantControls.filter((row: any) => Array.isArray(row.evidence) && row.evidence.length > 0).length,
      withEvidenceRequests: relevantControls.filter((row: any) => Array.isArray(row.evidenceRequests) && row.evidenceRequests.length > 0).length,
      failing: failingControls,
      inProgress: inProgressControls,
      notStarted: notStartedControls,
    },
    monitors: {
      total: monitors.length,
      byStatus: countBy(monitors, (row: any) => row.status),
      problemCount: problemMonitors.length,
      problemByControl: countBy(
        problemMonitors.flatMap((row: any) =>
          Array.isArray(row.controlSummaries) ? row.controlSummaries.map((control: any) => control.title).filter(Boolean) : [],
        ),
        (title: string) => title,
      ),
      problems: problemMonitors.map(compactProblemMonitor),
    },
    people: {
      total: members.length,
      byStatus: countBy(members, (row: any) => row.status),
      byRole: countBy(members, (row: any) => row.role),
    },
    vendors: {
      total: vendors.length,
      byStatus: countBy(vendors, statusOf),
      usingDataInventory: vendors.filter((row: any) => Boolean(row.usesDataInventory)).length,
      withServices: vendors.filter((row: any) => Array.isArray(row.services) && row.services.length > 0).length,
      withProcessingLocations: vendors.filter((row: any) => Array.isArray(row.processingLocations) && row.processingLocations.length > 0).length,
      withEvidence: vendors.filter((row: any) => Array.isArray(row.evidence) && row.evidence.length > 0).length,
    },
    evidence: {
      total: evidence.length,
      byType: countBy(evidence, (row: any) => row.type),
      byAiReviewStatus: countBy(evidence, (row: any) => row.aiReviewStatus),
      attachedToControls: evidence.filter((row: any) => Array.isArray(row.controlIds) && row.controlIds.length > 0).length,
      attachedToVendors: evidence.filter((row: any) => Array.isArray(row.vendorIds) && row.vendorIds.length > 0).length,
      error: errorOf(evidenceRaw),
    },
    policies: {
      total: policies.length,
      byStatus: countBy(policies, statusOf),
      error: errorOf(policiesRaw),
    },
    frameworks: {
      total: frameworks.length,
      names: frameworks.map((row: any) => row.name).filter(Boolean),
      error: errorOf(frameworksRaw),
    },
    accessReviews: {
      total: accessReviews.length,
      byStatus: countBy(accessReviews, statusOf),
      error: errorOf(accessReviewsRaw),
    },
    domains: {
      total: domains.length,
      byStatus: countBy(domains, statusOf),
      error: errorOf(domainsRaw),
    },
    integrations: {
      total: integrations.length,
      byStatus: countBy(integrations, integrationStatus),
      byCategory: countBy(integrations, (row: any) => row.integrationType?.category),
      partial: Boolean((integrationsRaw as any)?.isPartial),
      error: errorOf(integrationsRaw),
    },
    riskAssessments: {
      total: riskAssessments.length,
      byStatus: countBy(riskAssessments, statusOf),
      error: errorOf(riskAssessmentsRaw),
    },
    securityTraining: {
      moduleCount: trainingModules.length,
      userProgressCount: trainingProgress.length,
      progressByCompliance: countBy(trainingProgress, statusOf),
      error: errorOf(trainingModulesRaw) || errorOf(trainingProgressRaw),
    },
    trustCenter: {
      published: (trustConfigRaw as any)?.isPublished ?? null,
      documentCount: trustDocuments.length,
      documentRequestCount: trustDocumentRequests.length,
      faqCount: trustFaqs.length,
      securityIssueCount: trustSecurityIssues.length,
      error:
        errorOf(trustConfigRaw) ||
        errorOf(trustDocumentsRaw) ||
        errorOf(trustDocumentRequestsRaw) ||
        errorOf(trustFaqsRaw) ||
        errorOf(trustSecurityIssuesRaw),
    },
    reports: {
      total: reports.length,
      byStatus: countBy(reports, statusOf),
      error: errorOf(reportsRaw),
    },
    pentests: {
      hasActiveRequest: Boolean((pentestActiveRaw as any)?.request),
      error: errorOf(pentestActiveRaw),
    },
    codeSecurity: {
      hasScan: Boolean(codeScanRaw && !errorOf(codeScanRaw)),
      settingsKeys: codeSettingsRaw && !errorOf(codeSettingsRaw) ? Object.keys(codeSettingsRaw as Record<string, unknown>) : [],
      repositoryCount: gitRepositories.length,
      error: errorOf(codeScanRaw) || errorOf(codeSettingsRaw) || errorOf(gitRepositoriesRaw),
    },
    attackSurface: {
      stats: attackStats,
      returnedIssueCount: Array.isArray((attackIssues as any)?.issues) ? (attackIssues as any).issues.length : 0,
      totalIssueCount: (attackIssues as any)?.pagination?.total ?? null,
      pagination: (attackIssues as any)?.pagination || null,
      returnedScanCount: Array.isArray((attackScans as any)?.scans) ? (attackScans as any).scans.length : 0,
      totalScanCount: (attackScans as any)?.pagination?.total ?? null,
      scanPagination: (attackScans as any)?.pagination || null,
      error: errorOf(attackStats) || errorOf(attackIssues) || errorOf(attackScans),
    },
  };
}
