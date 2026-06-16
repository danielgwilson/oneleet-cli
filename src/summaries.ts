import { safeRowMeta } from "./safety.js";
import { countBy, integrationStatus, statusOf, summarizeCheckSummary } from "./report-helpers.js";

export function summarizeMembers(raw: any): unknown {
  if (!raw || !Array.isArray(raw.rows)) return raw;
  return {
    ...raw,
    rows: raw.rows.map((row: any, index: number) => ({
      ...safeRowMeta("member", index, row),
      hasName: Boolean(row.name || row.userPublic?.name),
      role: row.role || null,
      status: row.status || null,
      type: row.type || null,
      createdAt: row.createdAt || null,
      updatedAt: row.updatedAt || null,
    })),
  };
}

export function summarizeCurrentUser(raw: any): unknown {
  if (!raw || typeof raw !== "object") return raw;
  return {
    hasId: Boolean(raw.id),
    emailVerified: raw.emailVerified ?? null,
    oneleetRole: raw.oneleetRole ?? null,
    createdAt: raw.createdAt || null,
    updatedAt: raw.updatedAt || null,
    hasName: Boolean(raw.name),
    hasEmail: Boolean(raw.email),
  };
}

export function summarizeTenant(raw: any): unknown {
  if (!raw || typeof raw !== "object") return raw;
  return {
    hasId: Boolean(raw.id),
    hasName: Boolean(raw.name),
    hasSlug: Boolean(raw.slug || raw.recommendedSlug),
    createdAt: raw.createdAt || null,
    updatedAt: raw.updatedAt || null,
    onboardingStatus: raw.onboardingStatus || null,
    policyOnboardingStatus: raw.policyOnboardingStatus || null,
    completedOnboardingStepCount: Array.isArray(raw.completedOnboardingSteps) ? raw.completedOnboardingSteps.length : 0,
    skippedOnboardingStepCount: Array.isArray(raw.skippedOnboardingSteps) ? raw.skippedOnboardingSteps.length : 0,
    memberCount: Array.isArray(raw.members) ? raw.members.length : null,
    engagementCount: Array.isArray(raw.engagements) ? raw.engagements.length : null,
    sla: {
      accessReviewHours: raw.slaAccessReviewHours ?? null,
      criticalHours: raw.slaCriticalHours ?? null,
      highSeverityHours: raw.slaHighSeverityHours ?? null,
      mediumSeverityHours: raw.slaMediumSeverityHours ?? null,
      policySigningHours: raw.slaPolicySigningHours ?? null,
      riskAssessmentHours: raw.slaRiskAssessmentHours ?? null,
      securityTrainingHours: raw.slaSecurityTrainingHours ?? null,
      vendorAssessmentHours: raw.slaVendorAssessmentHours ?? null,
    },
  };
}

export function summarizeFrameworkStats(raw: any): unknown {
  if (!raw || typeof raw !== "object") return null;
  const controls = raw.controls && typeof raw.controls === "object" ? raw.controls : {};
  return {
    name: typeof raw.name === "string" ? raw.name : null,
    status: raw.status || raw.lifecycle || raw.state || null,
    passingControlsCount: raw.passingControlsCount ?? controls.passingCount ?? null,
    totalControlsCount: raw.totalControlsCount ?? controls.count ?? null,
    failingControlsCount: raw.failingControlsCount ?? controls.failingCount ?? null,
    inProgressControlsCount: raw.inProgressControlsCount ?? controls.inProgressCount ?? null,
    notStartedControlsCount: raw.notStartedControlsCount ?? controls.notStartedCount ?? null,
  };
}

export function summarizeEvidence(raw: any): unknown {
  const summarize = (row: any, index: number) => ({
    ...safeRowMeta("evidence", index, row),
    type: row.type || null,
    aiReviewStatus: row.aiReviewStatus || null,
    createdAt: row.createdAt || null,
    updatedAt: row.updatedAt || null,
    controlCount: Array.isArray(row.controlIds) ? row.controlIds.length : 0,
    vendorCount: Array.isArray(row.vendorIds) ? row.vendorIds.length : 0,
    hasFileName: Boolean(row.fileName),
    hasCreator: Boolean(row.createdBy),
  });
  if (Array.isArray(raw)) return raw.map(summarize);
  if (!raw || !Array.isArray(raw.rows)) return raw;
  return { ...raw, rows: raw.rows.map(summarize) };
}

export function summarizeControls(raw: any): unknown {
  if (!raw || !Array.isArray(raw.rows)) return raw;
  return {
    ...raw,
    rows: raw.rows.map((row: any, index: number) => ({
      ...safeRowMeta("control", index, row),
      title: row.title,
      category: row.category,
      status: row.status,
      frameworks: Array.isArray(row.tenantComplianceRequirements)
        ? Array.from(new Set(row.tenantComplianceRequirements.map((req: any) => req.frameworkName).filter(Boolean)))
        : [],
      references: Array.isArray(row.tenantComplianceRequirements)
        ? row.tenantComplianceRequirements.map((req: any) => req.referenceId).filter(Boolean)
        : [],
      checkSummary: summarizeCheckSummary(row.checkSummary),
      evidenceCount: Array.isArray(row.evidence) ? row.evidence.length : 0,
      evidenceRequestCount: Array.isArray(row.evidenceRequests) ? row.evidenceRequests.length : 0,
    })),
  };
}

export function summarizeMonitors(raw: any): unknown {
  if (!raw || !Array.isArray(raw.rows)) return raw;
  return {
    ...raw,
    rows: raw.rows.map((row: any, index: number) => summarizeMonitorRow(row, index)),
  };
}

export function summarizeMonitorRow(row: any, index: number): unknown {
  return {
    ...safeRowMeta("monitor", index, row),
    status: row.status,
    isEnabled: row.isEnabled,
    statusChangedAt: row.statusChangedAt || null,
    monitorType: row.monitorType?.name || null,
    rerunDisabled: row.monitorType?.rerunDisabled ?? null,
    controls: Array.isArray(row.controlSummaries) ? row.controlSummaries.map((control: any) => control.title).filter(Boolean) : [],
    assets: {
      count: row.stats?.assets?.count ?? null,
      failingCount: row.stats?.assets?.failingCount ?? null,
      passingCount: row.stats?.assets?.passingCount ?? null,
      percentPassing: row.stats?.assets?.percentPassing ?? null,
    },
    latestRunStatus: row.latestRun?.status || null,
    currentStateStatus: row.currentState?.status || null,
  };
}

export function summarizeVendors(raw: any): unknown {
  if (!raw || !Array.isArray(raw.rows)) return raw;
  return {
    ...raw,
    rows: raw.rows.map((row: any, index: number) => ({
      ...safeRowMeta("vendor", index, row),
      isCompleted: row.isCompleted,
      status: statusOf(row),
      risk: row.risk || null,
      hasVendorName: Boolean(row.vendor?.name),
      hasVendorUrl: Boolean(row.vendor?.url),
      vendorVerified: row.vendor?.verified ?? null,
      serviceCount: Array.isArray(row.services) ? row.services.length : 0,
      processingLocationCount: Array.isArray(row.processingLocations) ? row.processingLocations.length : 0,
      evidenceCount: Array.isArray(row.evidence) ? row.evidence.length : 0,
      hasCustomIntegrationConnection: Boolean(row.hasCustomIntegrationConnection),
      usesDataInventory: Boolean(row.usesDataInventory),
      createdAt: row.createdAt || null,
      updatedAt: row.updatedAt || null,
    })),
  };
}

export function summarizeDomains(raw: any): unknown {
  if (!raw || !Array.isArray(raw.rows)) return raw;
  return {
    ...raw,
    rows: raw.rows.map((row: any, index: number) => ({
      ...safeRowMeta("domain", index, row),
      status: statusOf(row),
      hasDomain: Boolean(row.domain || row.name || row.url),
      createdAt: row.createdAt || null,
      updatedAt: row.updatedAt || null,
    })),
  };
}

export function summarizeIntegrations(raw: any): unknown {
  if (!raw || !Array.isArray(raw.rows)) return raw;
  return {
    ...raw,
    rows: raw.rows.map((row: any, index: number) => ({
      ...safeRowMeta("integration", index, row),
      status: integrationStatus(row),
      integrationType: row.integrationType?.name || row.integrationTypeId || null,
      category: row.integrationType?.category || null,
      isOneleetManaged: row.integrationType?.isOneleetManaged ?? null,
      requiresOAuth: row.integrationType?.requiresOAuth ?? null,
      connectionCount: Array.isArray(row.connections) ? row.connections.length : 0,
      connectionStatusCounts: Array.isArray(row.connections) ? countBy(row.connections, (connection: any) => connection.status) : [],
      monitorCount: row.monitorCount ?? null,
      createdAt: row.createdAt || null,
      updatedAt: row.updatedAt || null,
    })),
  };
}

export function summarizeFrameworks(raw: any): unknown {
  return summarizeGenericRows(raw, "framework", (row) => {
    const controls = row.controls && typeof row.controls === "object" ? row.controls : {};
    return {
      name: row.name || row.frameworkName || null,
      status: statusOf(row),
      controlCount: row.totalControlsCount ?? controls.count ?? null,
      passingControlCount: row.passingControlsCount ?? controls.passingCount ?? null,
      failingControlCount: row.failingControlsCount ?? controls.failingCount ?? null,
      inProgressControlCount: row.inProgressControlsCount ?? controls.inProgressCount ?? null,
      notStartedControlCount: row.notStartedControlsCount ?? controls.notStartedCount ?? null,
    };
  });
}

export function summarizeRiskAssessments(raw: any): unknown {
  return summarizeGenericRows(raw, "risk-assessment", (row) => ({
    status: statusOf(row),
    risk: row.risk || row.riskLevel || row.severity || null,
    createdAt: row.createdAt || null,
    updatedAt: row.updatedAt || null,
    completedAt: row.completedAt || null,
    controlCount: Array.isArray(row.controls) ? row.controls.length : null,
    evidenceCount: Array.isArray(row.evidence) ? row.evidence.length : null,
    hasTitle: Boolean(row.title || row.name),
    hasOwner: Boolean(row.owner || row.assignee || row.responsibleUser),
  }));
}

export function summarizeSecurityTrainingProgress(raw: any): unknown {
  const summarize = (row: any, index: number) => ({
    ...safeRowMeta("training-progress", index, row),
    isCompliant: row.isCompliant,
    compliantAt: row.compliantAt || null,
    completedModuleCount: Array.isArray(row.completedModules) ? row.completedModules.length : 0,
  });
  if (Array.isArray(raw)) return raw.map(summarize);
  if (!raw || !Array.isArray(raw.rows)) return raw;
  return { ...raw, rows: raw.rows.map(summarize) };
}

export function summarizeSecurityTrainingModules(raw: any): unknown {
  const summarize = (row: any, index: number) => ({
    ...safeRowMeta("training-module", index, row),
    title: row.title || null,
    lifecycle: row.lifecycle || null,
    audience: row.audience || null,
    sectionCount: Array.isArray(row.sections) ? row.sections.length : 0,
    hasDescription: Boolean(row.description),
  });
  if (Array.isArray(raw)) return raw.map(summarize);
  if (!raw || !Array.isArray(raw.rows)) return raw;
  return { ...raw, rows: raw.rows.map(summarize) };
}

export function summarizePolicies(raw: any): unknown {
  return summarizeGenericRows(raw, "policy", (row) => ({
    title: row.title || row.name || null,
    status: statusOf(row),
    lifecycle: row.lifecycle || null,
    createdAt: row.createdAt || null,
    updatedAt: row.updatedAt || null,
    hasBody: Boolean(row.body || row.content || row.markdown),
  }));
}

export function summarizeAccessReviews(raw: any): unknown {
  return summarizeGenericRows(raw, "access-review", (row) => ({
    status: statusOf(row),
    createdAt: row.createdAt || null,
    updatedAt: row.updatedAt || null,
    completedAt: row.completedAt || null,
    accountCount: Array.isArray(row.accounts) ? row.accounts.length : null,
    reviewerCount: Array.isArray(row.reviewers) ? row.reviewers.length : null,
  }));
}

export function summarizeReports(raw: any): unknown {
  return summarizeGenericRows(raw, "report", (row) => ({
    type: row.type || null,
    status: statusOf(row),
    createdAt: row.createdAt || null,
    updatedAt: row.updatedAt || null,
    hasName: Boolean(row.name || row.title),
    hasFile: Boolean(row.fileName || row.file || row.url),
  }));
}

export function summarizeTrustRows(raw: any): unknown {
  return summarizeGenericRows(raw, "trust-row", (row) => ({
    status: statusOf(row),
    createdAt: row.createdAt || null,
    updatedAt: row.updatedAt || null,
    hasTitle: Boolean(row.title || row.question || row.name),
    hasBody: Boolean(row.body || row.answer || row.description || row.content),
    hasFile: Boolean(row.fileName || row.file || row.url),
  }));
}

export function summarizeCodeScan(raw: any): unknown {
  if (!raw || typeof raw !== "object") return raw;
  return {
    hasId: Boolean(raw.id),
    status: statusOf(raw),
    createdAt: raw.createdAt || null,
    updatedAt: raw.updatedAt || null,
    hasRepositoryData: Boolean(raw.repository || raw.repositories),
    issueCount: Array.isArray(raw.issues) ? raw.issues.length : raw.issueCount ?? null,
  };
}

export function summarizeCodeRepositories(raw: any): unknown {
  return summarizeGenericRows(raw, "code-repository", (row) => ({
    provider: row.provider || row.integrationType || null,
    status: statusOf(row),
    createdAt: row.createdAt || null,
    updatedAt: row.updatedAt || null,
    hasName: Boolean(row.name || row.fullName),
    hasUrl: Boolean(row.url || row.htmlUrl),
  }));
}

export function summarizePentestRequest(raw: any): unknown {
  if (!raw || typeof raw !== "object") return raw;
  const request = raw.request;
  if (!request) return { hasActiveRequest: false };
  return {
    hasActiveRequest: true,
    request: {
      hasId: Boolean(request.id),
      status: statusOf(request),
      createdAt: request.createdAt || null,
      updatedAt: request.updatedAt || null,
    },
  };
}

function summarizeGenericRows(raw: any, prefix: string, mapper: (row: any) => Record<string, unknown>): unknown {
  const summarize = (row: any, index: number) => ({ ...safeRowMeta(prefix, index, row), ...mapper(row) });
  if (Array.isArray(raw)) return raw.map(summarize);
  if (raw && typeof raw === "object" && "rows" in raw && raw.rows == null) return { ...raw, rows: [] };
  if (!raw || !Array.isArray(raw.rows)) return raw;
  return { ...raw, rows: raw.rows.map(summarize) };
}

export function summarizeTrustConfig(raw: any): unknown {
  if (!raw || typeof raw !== "object") return raw;
  return {
    isPublished: raw.isPublished ?? null,
    hasEmail: Boolean(raw.email),
    hasBacklink: Boolean(raw.backlink),
    hasCustomTitle: Boolean(raw.customTitle),
    hasCustomDescription: Boolean(raw.customDescription),
    subprocessorTenantVendorCount: Array.isArray(raw.subprocessorTenantVendorIds) ? raw.subprocessorTenantVendorIds.length : 0,
  };
}

export function summarizeAttackSurfaceIssues(raw: any): unknown {
  if (!raw || !Array.isArray(raw.issues)) return raw;
  return {
    pagination: raw.pagination || null,
    groups: raw.groups || null,
    facets: raw.facets || null,
    issues: raw.issues.map((issue: any, index: number) => ({
      ...safeRowMeta("attack-issue", index, issue),
      title: issue.title || null,
      severity: issue.severity || null,
      status: issue.status || null,
      cveId: issue.cveId || null,
      cweId: issue.cweId || null,
      cvssScore: issue.cvssScore ?? null,
      detectedAt: issue.detectedAt || null,
      lastSeenAt: issue.lastSeenAt || null,
      resolvedAt: issue.resolvedAt || null,
      hasAffectedUrl: Boolean(issue.affectedUrl),
      hasService: Boolean(issue.service),
    })),
  };
}

export function summarizeAttackSurfaceScans(raw: any): unknown {
  if (!raw || !Array.isArray(raw.scans)) return raw;
  return {
    pagination: raw.pagination || null,
    nextScheduled: raw.nextScheduled || null,
    groups: raw.groups || null,
    scans: raw.scans.map((scan: any, index: number) => ({
      ...safeRowMeta("attack-scan", index, scan),
      type: scan.type || null,
      status: scan.status || null,
      startedAt: scan.startedAt || null,
      completedAt: scan.completedAt || null,
      durationMinutes: scan.durationMinutes ?? null,
      totalAssetsFound: scan.totalAssetsFound ?? null,
      totalFindingsFound: scan.totalFindingsFound ?? null,
      totalIssuesFound: scan.totalIssuesFound ?? null,
      totalServicesAffected: scan.totalServicesAffected ?? null,
      totalServicesFound: scan.totalServicesFound ?? null,
      criticalIssuesFound: scan.criticalIssuesFound ?? null,
      highIssuesFound: scan.highIssuesFound ?? null,
      mediumIssuesFound: scan.mediumIssuesFound ?? null,
      lowIssuesFound: scan.lowIssuesFound ?? null,
      hasTargetDomains: Array.isArray(scan.targetDomains) && scan.targetDomains.length > 0,
    })),
  };
}
