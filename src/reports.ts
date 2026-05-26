import { OneleetApiClient } from "./oneleet-api.js";
import { assertSafeAggregateReport } from "./safety.js";
import {
  compactProblemMonitor,
  countBy,
  countWhere,
  errorOf,
  integrationStatus,
  keyedCompleteness,
  listCompleteness,
  mergeCompleteness,
  openAttackIssues,
  optionalRead,
  rowsOf,
  sourceError,
  sourceStatus,
  statusOf,
} from "./report-helpers.js";

export async function buildWorkforceSummary(client: OneleetApiClient, tenantId: string): Promise<Record<string, unknown>> {
  const [membersRaw, accessReviewsRaw, trainingModulesRaw, trainingProgressRaw, monitorsRaw, integrationsRaw] = await Promise.all([
    client.listMembers(tenantId),
    optionalRead(client.listAccessReviews(tenantId)),
    optionalRead(client.listSecurityTrainingModules(tenantId)),
    optionalRead(client.listSecurityTrainingProgress(tenantId)),
    optionalRead(client.listMonitors(tenantId)),
    optionalRead(client.listIntegrations(tenantId)),
  ]);
  const members = rowsOf(membersRaw);
  const accessReviews = rowsOf(accessReviewsRaw);
  const trainingModules = rowsOf(trainingModulesRaw);
  const trainingProgress = rowsOf(trainingProgressRaw);
  const monitors = rowsOf(monitorsRaw);
  const integrations = rowsOf(integrationsRaw);
  const problemMonitors = monitors.filter((row: any) => row.status === "ALERTING" || row.status === "BREACHING_SLA");
  const failedIntegrations = integrations.filter((row: any) => integrationStatus(row) === "FAILED");

  const report = {
    generatedAt: new Date().toISOString(),
    completeness: listCompleteness({
      members: membersRaw,
      accessReviews: accessReviewsRaw,
      securityTrainingModules: trainingModulesRaw,
      securityTrainingProgress: trainingProgressRaw,
      monitors: monitorsRaw,
      integrations: integrationsRaw,
    }),
    people: {
      total: members.length,
      byStatus: countBy(members, (row: any) => row.status),
      byRole: countBy(members, (row: any) => row.role),
      withName: countWhere(members, (row: any) => Boolean(row.name || row.userPublic?.name)),
      withEmail: countWhere(members, (row: any) => Boolean(row.email || row.userPublic?.email)),
    },
    accessReviews: {
      total: accessReviews.length,
      byStatus: countBy(accessReviews, statusOf),
    },
    securityTraining: {
      moduleCount: trainingModules.length,
      userProgressCount: trainingProgress.length,
      progressByCompliance: countBy(trainingProgress, statusOf),
      nonCompliantCount: countWhere(trainingProgress, (row: any) => statusOf(row) === "NON_COMPLIANT"),
    },
    monitors: {
      total: monitors.length,
      byStatus: countBy(monitors, (row: any) => row.status),
      problemCount: problemMonitors.length,
      ownershipSignal: {
        ownerFieldsObserved: countWhere(monitors, (row: any) => Boolean(row.owner || row.assignee || row.responsibleUser || row.team)),
        note: "Monitor ownership is not a reliable typed field in observed payloads; treat follow-up owner as unresolved unless Oneleet exposes a richer detail surface.",
      },
    },
    integrations: {
      total: integrations.length,
      byStatus: countBy(integrations, integrationStatus),
      failedCount: failedIntegrations.length,
      connectionCount: integrations.reduce((sum: number, row: any) => sum + (Array.isArray(row.connections) ? row.connections.length : 0), 0),
    },
    followUp: {
      nonCompliantTrainingUsers: countWhere(trainingProgress, (row: any) => statusOf(row) === "NON_COMPLIANT"),
      invitedOrInactiveMembers: countWhere(members, (row: any) => row.status !== "ACTIVE"),
      openAccessReviews: countWhere(accessReviews, (row: any) => !["COMPLETED", "CLOSED", "DONE"].includes(statusOf(row))),
      monitorProblems: problemMonitors.length,
      failedIntegrations: failedIntegrations.length,
    },
  };
  assertSafeAggregateReport(report, "Workforce summary");
  return report;
}

export async function buildVendorRiskReport(client: OneleetApiClient, tenantId: string): Promise<Record<string, unknown>> {
  const [vendorsRaw, evidenceRaw, accessReviewsRaw, riskAssessmentsRaw, policiesRaw, trustDocumentsRaw, reportsRaw] = await Promise.all([
    client.listVendors(tenantId),
    optionalRead(client.listEvidence(tenantId)),
    optionalRead(client.listAccessReviews(tenantId)),
    optionalRead(client.listRiskAssessments(tenantId)),
    optionalRead(client.listPolicies(tenantId)),
    optionalRead(client.listTrustDocuments(tenantId)),
    optionalRead(client.listReports(tenantId)),
  ]);
  const vendors = rowsOf(vendorsRaw);
  const evidence = rowsOf(evidenceRaw);
  const accessReviews = rowsOf(accessReviewsRaw);
  const riskAssessments = rowsOf(riskAssessmentsRaw);
  const policies = rowsOf(policiesRaw);
  const trustDocuments = rowsOf(trustDocumentsRaw);
  const reports = rowsOf(reportsRaw);

  const report = {
    generatedAt: new Date().toISOString(),
    completeness: listCompleteness({
      vendors: vendorsRaw,
      evidence: evidenceRaw,
      accessReviews: accessReviewsRaw,
      riskAssessments: riskAssessmentsRaw,
      policies: policiesRaw,
      trustDocuments: trustDocumentsRaw,
      reports: reportsRaw,
    }),
    vendors: {
      total: vendors.length,
      byStatus: countBy(vendors, statusOf),
      byRisk: countBy(vendors, (row: any) => row.risk || row.riskLevel || "UNKNOWN"),
      completed: countWhere(vendors, (row: any) => Boolean(row.isCompleted)),
      usingDataInventory: countWhere(vendors, (row: any) => Boolean(row.usesDataInventory)),
      withServices: countWhere(vendors, (row: any) => Array.isArray(row.services) && row.services.length > 0),
      withProcessingLocations: countWhere(vendors, (row: any) => Array.isArray(row.processingLocations) && row.processingLocations.length > 0),
      withEvidence: countWhere(vendors, (row: any) => Array.isArray(row.evidence) && row.evidence.length > 0),
      withCustomIntegrationConnection: countWhere(vendors, (row: any) => Boolean(row.hasCustomIntegrationConnection)),
    },
    evidence: {
      total: evidence.length,
      attachedToVendors: countWhere(evidence, (row: any) => Array.isArray(row.vendorIds) && row.vendorIds.length > 0),
      byType: countBy(evidence, (row: any) => row.type),
      byAiReviewStatus: countBy(evidence, (row: any) => row.aiReviewStatus),
    },
    relatedProgramInputs: {
      accessReviewCount: accessReviews.length,
      riskAssessmentCount: riskAssessments.length,
      policyCount: policies.length,
      trustDocumentCount: trustDocuments.length,
      reportCount: reports.length,
    },
    caveats: [
      "BAA/privacy status is not a first-class typed field in the current summarized vendor surface.",
      "Data inventory linkage is only represented by vendor-level counts/booleans until a dedicated data-inventory surface is typed.",
      "No vendor names, domains, file names, or evidence text are emitted by this report.",
    ],
  };
  assertSafeAggregateReport(report, "Vendor-risk report");
  return report;
}

export async function buildTrustReadiness(client: OneleetApiClient, tenantId: string): Promise<Record<string, unknown>> {
  const [
    trustConfigRaw,
    trustDocumentsRaw,
    trustDocumentRequestsRaw,
    trustFaqsRaw,
    trustSecurityIssuesRaw,
    reportsRaw,
    policiesRaw,
    evidenceRaw,
    controlsRaw,
    monitorsRaw,
    trainingProgressRaw,
    attackStatsRaw,
    attackIssuesRaw,
    codeScanRaw,
    pentestActiveRaw,
  ] = await Promise.all([
    client.getTrustConfig(tenantId),
    optionalRead(client.listTrustDocuments(tenantId)),
    optionalRead(client.listTrustDocumentRequests(tenantId)),
    optionalRead(client.listTrustFaqs(tenantId)),
    optionalRead(client.listTrustSecurityIssues(tenantId)),
    optionalRead(client.listReports(tenantId)),
    optionalRead(client.listPolicies(tenantId)),
    optionalRead(client.listEvidence(tenantId)),
    optionalRead(client.listControls(tenantId)),
    optionalRead(client.listMonitors(tenantId)),
    optionalRead(client.listSecurityTrainingProgress(tenantId)),
    optionalRead(client.getAttackSurfaceStats(tenantId)),
    optionalRead(client.listAttackSurfaceIssues(tenantId, { limit: 1000 })),
    optionalRead(client.getCodeSecurityScan(tenantId)),
    optionalRead(client.getActivePentestRequest(tenantId)),
  ]);
  const trustConfig = trustConfigRaw && typeof trustConfigRaw === "object" ? (trustConfigRaw as any) : {};
  const trustDocuments = rowsOf(trustDocumentsRaw);
  const trustDocumentRequests = rowsOf(trustDocumentRequestsRaw);
  const trustFaqs = rowsOf(trustFaqsRaw);
  const trustSecurityIssues = rowsOf(trustSecurityIssuesRaw);
  const reports = rowsOf(reportsRaw);
  const policies = rowsOf(policiesRaw);
  const evidence = rowsOf(evidenceRaw);
  const controls = rowsOf(controlsRaw);
  const monitors = rowsOf(monitorsRaw);
  const trainingProgress = rowsOf(trainingProgressRaw);
  const openIssues = openAttackIssues(attackIssuesRaw);
  const failingControls = controls.filter((row: any) => row.status === "FAILING");
  const notStartedControls = controls.filter((row: any) => row.status === "NOT_STARTED");
  const problemMonitors = monitors.filter((row: any) => row.status === "ALERTING" || row.status === "BREACHING_SLA");
  const blockers = [
    trustConfig.isPublished ? null : "Trust center is not marked published.",
    trustDocuments.length > 0 ? null : "No trust documents are visible through the typed adapter.",
    reports.length > 0 ? null : "No reports are visible through the typed adapter.",
    policies.length > 0 ? null : "No tenant policies are visible through the typed adapter.",
    failingControls.length === 0 ? null : "Controls are failing.",
    notStartedControls.length === 0 ? null : "Controls are not started.",
    problemMonitors.length === 0 ? null : "Monitor problems are present.",
    countWhere(trainingProgress, (row: any) => statusOf(row) === "NON_COMPLIANT") === 0 ? null : "Security training has non-compliant users.",
    openIssues.length === 0 ? null : "Attack-surface issues are open.",
    codeScanRaw && !errorOf(codeScanRaw) ? null : "No code-security scan is visible.",
    (pentestActiveRaw as any)?.request ? null : "No active pentest request is visible.",
  ].filter(Boolean);

  const report = {
    generatedAt: new Date().toISOString(),
    completeness: mergeCompleteness(
      listCompleteness({
        trustDocuments: trustDocumentsRaw,
        trustDocumentRequests: trustDocumentRequestsRaw,
        trustFaqs: trustFaqsRaw,
        trustSecurityIssues: trustSecurityIssuesRaw,
        reports: reportsRaw,
        policies: policiesRaw,
        evidence: evidenceRaw,
        controls: controlsRaw,
        monitors: monitorsRaw,
        securityTrainingProgress: trainingProgressRaw,
      }),
      keyedCompleteness({ attackSurfaceIssues: { value: attackIssuesRaw, key: "issues" } }),
    ),
    trustCenter: {
      published: trustConfig.isPublished ?? null,
      hasEmail: Boolean(trustConfig.email),
      hasBacklink: Boolean(trustConfig.backlink),
      hasCustomTitle: Boolean(trustConfig.customTitle),
      hasCustomDescription: Boolean(trustConfig.customDescription),
      documentCount: trustDocuments.length,
      documentRequestCount: trustDocumentRequests.length,
      faqCount: trustFaqs.length,
      securityIssueCount: trustSecurityIssues.length,
      reportCount: reports.length,
    },
    packetInputs: {
      policyCount: policies.length,
      evidenceCount: evidence.length,
      controlsFailing: failingControls.length,
      controlsNotStarted: notStartedControls.length,
      monitorProblemCount: problemMonitors.length,
      nonCompliantTrainingUsers: countWhere(trainingProgress, (row: any) => statusOf(row) === "NON_COMPLIANT"),
      openAttackSurfaceIssues: openIssues.length,
      codeSecurityScanPresent: Boolean(codeScanRaw && !errorOf(codeScanRaw)),
      activePentestRequestPresent: Boolean((pentestActiveRaw as any)?.request),
      attackSurfaceStatsPresent: Boolean(attackStatsRaw && !errorOf(attackStatsRaw)),
    },
    readiness: {
      customerReady: blockers.length === 0,
      blockerCount: blockers.length,
      blockers,
    },
  };
  assertSafeAggregateReport(report, "Trust readiness report");
  return report;
}

export async function buildSecurityRemediationQueue(client: OneleetApiClient, tenantId: string): Promise<Record<string, unknown>> {
  const [controlsRaw, monitorsRaw, integrationsRaw, domainsRaw, attackStatsRaw, attackIssuesRaw, attackScansRaw, codeScanRaw, codeSettingsRaw, gitRepositoriesRaw, pentestActiveRaw] =
    await Promise.all([
      client.listControls(tenantId),
      client.listMonitors(tenantId),
      client.listIntegrations(tenantId),
      client.listDomains(tenantId),
      optionalRead(client.getAttackSurfaceStats(tenantId)),
      optionalRead(client.listAttackSurfaceIssues(tenantId, { limit: 1000 })),
      optionalRead(client.listAttackSurfaceScans(tenantId, { limit: 1000 })),
      optionalRead(client.getCodeSecurityScan(tenantId)),
      optionalRead(client.getCodeSecuritySettings(tenantId)),
      optionalRead(client.listGitRepositories(tenantId)),
      optionalRead(client.getActivePentestRequest(tenantId)),
    ]);
  const controls = rowsOf(controlsRaw);
  const monitors = rowsOf(monitorsRaw);
  const integrations = rowsOf(integrationsRaw);
  const domains = rowsOf(domainsRaw);
  const attackIssues = Array.isArray((attackIssuesRaw as any)?.issues) ? (attackIssuesRaw as any).issues : [];
  const attackScans = Array.isArray((attackScansRaw as any)?.scans) ? (attackScansRaw as any).scans : [];
  const gitRepositories = rowsOf(gitRepositoriesRaw);
  const failingControls = controls.filter((row: any) => row.status === "FAILING");
  const notStartedControls = controls.filter((row: any) => row.status === "NOT_STARTED");
  const problemMonitors = monitors.filter((row: any) => row.status === "ALERTING" || row.status === "BREACHING_SLA");
  const failedIntegrations = integrations.filter((row: any) => integrationStatus(row) === "FAILED");
  const openIssues = openAttackIssues(attackIssuesRaw);
  const codeScanPresent = Boolean(codeScanRaw && !errorOf(codeScanRaw));
  const codeRepoCount = gitRepositories.length;
  const lanes = [
    failingControls.length > 0
      ? { lane: "controls", priority: "high", count: failingControls.length, signal: "failing controls need remediation or exception review" }
      : null,
    notStartedControls.length > 0
      ? { lane: "controls", priority: "medium", count: notStartedControls.length, signal: "not-started controls need implementation planning" }
      : null,
    problemMonitors.length > 0
      ? { lane: "monitors", priority: "high", count: problemMonitors.length, signal: "alerting or SLA-breaching monitors need triage" }
      : null,
    openIssues.length > 0
      ? { lane: "attack-surface", priority: "medium", count: openIssues.length, signal: "open attack-surface issues need triage" }
      : null,
    failedIntegrations.length > 0
      ? { lane: "integrations", priority: "medium", count: failedIntegrations.length, signal: "failed integrations may block automation or evidence" }
      : null,
    !codeScanPresent ? { lane: "code-security", priority: "medium", count: 1, signal: "no code-security scan is visible" } : null,
    codeRepoCount === 0 ? { lane: "code-security", priority: "medium", count: 1, signal: "no code repositories are visible" } : null,
    !(pentestActiveRaw as any)?.request ? { lane: "pentest", priority: "low", count: 1, signal: "no active pentest request is visible" } : null,
  ].filter(Boolean);

  const report = {
    generatedAt: new Date().toISOString(),
    completeness: mergeCompleteness(
      listCompleteness({
        controls: controlsRaw,
        monitors: monitorsRaw,
        integrations: integrationsRaw,
        domains: domainsRaw,
        gitRepositories: gitRepositoriesRaw,
      }),
      keyedCompleteness({
        attackSurfaceIssues: { value: attackIssuesRaw, key: "issues" },
        attackSurfaceScans: { value: attackScansRaw, key: "scans" },
      }),
    ),
    lanes,
    controls: {
      total: controls.length,
      byStatus: countBy(controls, (row: any) => row.status),
      failing: failingControls.length,
      notStarted: notStartedControls.length,
    },
    monitors: {
      total: monitors.length,
      byStatus: countBy(monitors, (row: any) => row.status),
      problemCount: problemMonitors.length,
    },
    attackSurface: {
      statsPresent: Boolean(attackStatsRaw && !errorOf(attackStatsRaw)),
      issuesReturned: attackIssues.length,
      openIssueCount: openIssues.length,
      bySeverity: countBy(attackIssues, (row: any) => row.severity),
      byStatus: countBy(attackIssues, statusOf),
      scansReturned: attackScans.length,
    },
    codeSecurity: {
      scanPresent: codeScanPresent,
      repositoryCount: codeRepoCount,
      settingsPresent: Boolean(codeSettingsRaw && !errorOf(codeSettingsRaw)),
    },
    integrations: {
      total: integrations.length,
      byStatus: countBy(integrations, integrationStatus),
      failedCount: failedIntegrations.length,
    },
    domains: {
      total: domains.length,
      byStatus: countBy(domains, statusOf),
    },
    pentest: {
      activeRequestPresent: Boolean((pentestActiveRaw as any)?.request),
    },
  };
  assertSafeAggregateReport(report, "Security remediation queue");
  return report;
}

export async function buildCoverageCheck(client: OneleetApiClient, tenantId: string): Promise<Record<string, unknown>> {
  const [
    dashboardRaw,
    controlsRaw,
    monitorsRaw,
    membersRaw,
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
    attackStatsRaw,
    attackIssuesRaw,
    attackScansRaw,
  ] = await Promise.all([
    optionalRead(client.getDashboard(tenantId)),
    optionalRead(client.listControls(tenantId)),
    optionalRead(client.listMonitors(tenantId)),
    optionalRead(client.listMembers(tenantId)),
    optionalRead(client.listVendors(tenantId)),
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
  const listSources = {
    controls: controlsRaw,
    monitors: monitorsRaw,
    people: membersRaw,
    vendors: vendorsRaw,
    evidence: evidenceRaw,
    policies: policiesRaw,
    frameworks: frameworksRaw,
    accessReviews: accessReviewsRaw,
    domains: domainsRaw,
    integrations: integrationsRaw,
    riskAssessments: riskAssessmentsRaw,
    securityTrainingModules: trainingModulesRaw,
    securityTrainingProgress: trainingProgressRaw,
    trustDocuments: trustDocumentsRaw,
    trustDocumentRequests: trustDocumentRequestsRaw,
    trustFaqs: trustFaqsRaw,
    trustSecurityIssues: trustSecurityIssuesRaw,
    reports: reportsRaw,
    gitRepositories: gitRepositoriesRaw,
  };
  const objectSources = {
    dashboard: dashboardRaw,
    trustConfig: trustConfigRaw,
    pentestActiveRequest: pentestActiveRaw,
    codeSecurityScan: codeScanRaw,
    codeSecuritySettings: codeSettingsRaw,
    attackSurfaceStats: attackStatsRaw,
  };
  const objectSourceErrors = Object.entries(objectSources).map(([source, value]) => sourceError(source, value)).filter(Boolean);
  const report = {
    generatedAt: new Date().toISOString(),
    completeness: mergeCompleteness(
      listCompleteness(listSources),
      keyedCompleteness({
        attackSurfaceIssues: { value: attackIssuesRaw, key: "issues" },
        attackSurfaceScans: { value: attackScansRaw, key: "scans" },
      }),
      { sourceErrors: objectSourceErrors, shapeErrors: [], paginationGaps: [] },
    ),
    sources: [
      ...Object.entries(objectSources).map(([source, value]) => sourceStatus(source, value, "object")),
      ...Object.entries(listSources).map(([source, value]) => sourceStatus(source, value, "list")),
      sourceStatus("attackSurfaceIssues", attackIssuesRaw, "keyed-list", "issues"),
      sourceStatus("attackSurfaceScans", attackScansRaw, "keyed-list", "scans"),
    ],
    scenarios: [
      { name: "hipaa-report", command: "hipaa report --json", grade: "A", status: "implemented" },
      { name: "workforce-access-training", command: "ops workforce-summary --json", grade: "A-", status: "implemented" },
      { name: "vendor-risk-privacy", command: "vendor-risk report --json", grade: "A-", status: "implemented" },
      { name: "trust-customer-packet", command: "trust readiness --json", grade: "A-", status: "implemented" },
      { name: "security-remediation", command: "security remediation-queue --json", grade: "A-", status: "implemented" },
      { name: "detail-drilldown", command: null, grade: "C", status: "queued" },
      { name: "mutations", command: null, grade: "out-of-scope", status: "deferred" },
    ],
  };
  assertSafeAggregateReport(report, "Coverage check");
  return report;
}

