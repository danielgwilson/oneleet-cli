import { Command } from "commander";
import { importFromCdp, saveAndValidate, validateConfig } from "./auth.js";
import { clearConfig, getDisplayConfigPath, resolveConfig } from "./config.js";
import { buildHipaaReport, writeHipaaReportOutput, type HipaaReportOptions } from "./hipaa-report.js";
import { codeError, makeError, ok, printJson } from "./output.js";
import {
  buildCoverageCheck,
  buildSecurityRemediationQueue,
  buildTrustReadiness,
  buildVendorRiskReport,
  buildWorkforceSummary,
} from "./reports.js";
import {
  clientFor,
  collect,
  configureParserContract,
  getCliVersion,
  jsonRequested,
  parsePositiveInteger,
  parseQueryPairs,
  printFailure,
  render,
  requireConfig,
  runJsonAction,
  tenantIdFor,
  wantsJsonOutput,
  type JsonOptions,
  type TenantOptions,
} from "./cli-runtime.js";
import {
  summarizeAccessReviews,
  summarizeAttackSurfaceIssues,
  summarizeAttackSurfaceScans,
  summarizeCodeRepositories,
  summarizeCodeScan,
  summarizeControls,
  summarizeCurrentUser,
  summarizeDomains,
  summarizeEvidence,
  summarizeFrameworks,
  summarizeIntegrations,
  summarizeMembers,
  summarizeMonitors,
  summarizePentestRequest,
  summarizePolicies,
  summarizeReports,
  summarizeRiskAssessments,
  summarizeSecurityTrainingModules,
  summarizeSecurityTrainingProgress,
  summarizeTenant,
  summarizeTrustConfig,
  summarizeTrustRows,
  summarizeVendors,
} from "./summaries.js";

export function buildProgram(): Command {
  const program = new Command();
  program
    .name("oneleet")
    .description("Agent-first private-surface CLI for Oneleet read workflows")
    .version(getCliVersion())
    .option("--json", "Print JSON envelope for command results and parser errors")
    .configureOutput({
      writeErr: (str) => {
        if (!wantsJsonOutput()) process.stderr.write(str);
      },
    })
    .exitOverride()
    .addHelpText(
      "after",
      `
  Safe first commands:
    oneleet auth status --json
    oneleet doctor --json
    oneleet coverage check --json
    oneleet hipaa report --json
  
  Scenario reports:
    oneleet ops workforce-summary --json
    oneleet vendor-risk report --json
    oneleet trust readiness --json
    oneleet security remediation-queue --json
  
  Raw output warning:
    Prefer summarized defaults. Use --raw or api get --unsafe-raw only for short-lived local debugging.
  `,
    );
  
  const auth = new Command("auth").description("Auth commands");
  auth
    .command("import-cdp")
    .description("Import the oneleet-app session cookie from a logged-in Chrome remote debugging session")
    .option("--host <host>", "CDP host", "127.0.0.1")
    .option("--port <port>", "CDP port", "9333")
    .option("--json", "Print JSON envelope")
    .action(async (opts: JsonOptions & { host: string; port: string }) => {
      await runJsonAction(async () => {
        const config = await importFromCdp({ host: opts.host, port: Number(opts.port) });
        const saved = await saveAndValidate(config);
        return {
          saved: saved.saved,
          tenantIdConfigured: Boolean(saved.config.tenantId),
          configPath: getDisplayConfigPath(),
          hasOneleetAppCookie: Boolean(saved.config.oneleetAppCookie),
          validation: saved.validation,
        };
      }, opts);
    });
  
  auth
    .command("status")
    .description("Show local auth status")
    .option("--json", "Print JSON envelope")
    .action(async (opts: JsonOptions) => {
      const config = await resolveConfig();
      const validation = config.oneleetAppCookie ? await validateConfig(config) : { ok: false, reason: "Missing oneleet-app cookie" };
        const data = {
          hasOneleetAppCookie: Boolean(config.oneleetAppCookie),
          tenantIdConfigured: Boolean(config.tenantId),
          source: config.source,
          configPath: getDisplayConfigPath(),
          validation,
      };
      if (jsonRequested(opts)) printJson(ok(data));
      else printJson(data);
    });
  
  auth
    .command("clear")
    .description("Clear saved Oneleet auth")
    .option("--json", "Print JSON envelope")
    .action(async (opts: JsonOptions) => {
      await clearConfig();
      render({ cleared: true }, opts);
    });
  
  program.addCommand(auth);
  
  program
    .command("doctor")
    .description("Validate auth and core Oneleet read endpoints")
    .option("--json", "Print JSON envelope")
    .action(async (opts: JsonOptions) => {
      try {
        const config = await requireConfig(opts);
        const validation = await validateConfig(config);
        const data = { validation, tenantIdConfigured: Boolean(config.tenantId), configPath: getDisplayConfigPath() };
        if (!validation.ok) {
          const code = validation.errorCode || "CHECK_FAILED";
          const message = validation.reason || "Oneleet doctor checks failed";
          printFailure(makeError(codeError(code, message)), opts, code === "AUTH_INVALID" || code === "AUTH_MISSING" ? 2 : 1);
          return;
        }
        render(data, opts);
      } catch (error: any) {
        const cliError = makeError(error);
        printFailure(cliError, opts, cliError.code === "AUTH_INVALID" || cliError.code === "AUTH_MISSING" ? 2 : 1);
      }
    });
  
  program
    .command("whoami")
    .description("Read the current Oneleet user")
    .option("--raw", "Return full upstream current-user row instead of summarized row")
    .option("--json", "Print JSON envelope")
    .action(async (opts: JsonOptions & { raw?: boolean }) => {
      await runJsonAction(async () => {
        const data = await clientFor(await requireConfig(opts)).getCurrentUser();
        return opts.raw ? data : summarizeCurrentUser(data);
      }, opts);
    });
  
  program
    .command("tenant")
    .description("Tenant commands")
    .addCommand(
      new Command("get")
        .option("--tenant-id <id>", "Tenant id override")
        .option("--raw", "Return full upstream tenant row instead of summarized row")
        .option("--json", "Print JSON envelope")
        .action(async (opts: TenantOptions & { raw?: boolean }) => {
          await runJsonAction(async () => {
            const config = await requireConfig(opts);
            const data = await clientFor(config).getTenant(opts.tenantId || config.tenantId);
            return opts.raw ? data : summarizeTenant(data);
          }, opts);
        }),
    );
  
  program
    .command("dashboard")
    .description("Read Oneleet dashboard summary")
    .option("--tenant-id <id>", "Tenant id override")
    .option("--json", "Print JSON envelope")
    .action(async (opts: TenantOptions) => {
      await runJsonAction(async () => {
        const config = await requireConfig(opts);
        return clientFor(config).getDashboard(opts.tenantId || config.tenantId);
      }, opts);
    });
  
  const hipaa = new Command("hipaa").description("HIPAA aggregate commands");
  hipaa
    .command("report")
    .description("Build a read-only HIPAA status report from Oneleet data")
    .option("--tenant-id <id>", "Tenant id override")
    .option("--format <format>", "Output format: json or markdown", "json")
    .option("--out <path>", "Write Markdown report to a file")
    .option("--json", "Print JSON envelope")
    .action(async (opts: HipaaReportOptions) => {
      await runJsonAction(async () => {
        const config = await requireConfig(opts);
        const tenantId = opts.tenantId || config.tenantId;
        const client = clientFor(config);
        return buildHipaaReport(client, tenantId);
      }, opts, async (report) => writeHipaaReportOutput(report, opts));
    });
  program.addCommand(hipaa);
  
  program
    .command("coverage")
    .description("Adapter coverage and drift checks")
    .addCommand(
      new Command("check")
        .description("Run a sanitized health check across all typed read surfaces")
        .option("--tenant-id <id>", "Tenant id override")
        .option("--json", "Print JSON envelope")
        .action(async (opts: TenantOptions) => {
          await runJsonAction(async () => {
            const config = await requireConfig(opts);
            return buildCoverageCheck(clientFor(config), tenantIdFor(opts, config));
          }, opts);
        }),
    );
  
  const ops = new Command("ops").description("Operational aggregate reports");
  ops
    .command("workforce-summary")
    .description("Build a sanitized workforce, access-review, training, monitor, and integration follow-up summary")
    .option("--tenant-id <id>", "Tenant id override")
    .option("--json", "Print JSON envelope")
    .action(async (opts: TenantOptions) => {
      await runJsonAction(async () => {
        const config = await requireConfig(opts);
        return buildWorkforceSummary(clientFor(config), tenantIdFor(opts, config));
      }, opts);
    });
  program.addCommand(ops);
  
  program
    .command("vendor-risk")
    .description("Vendor risk aggregate reports")
    .addCommand(
      new Command("report")
        .description("Build a sanitized vendor-risk, data-inventory, evidence, and privacy/BAA coverage report")
        .option("--tenant-id <id>", "Tenant id override")
        .option("--json", "Print JSON envelope")
        .action(async (opts: TenantOptions) => {
          await runJsonAction(async () => {
            const config = await requireConfig(opts);
            return buildVendorRiskReport(clientFor(config), tenantIdFor(opts, config));
          }, opts);
        }),
    );
  
  program
    .command("security")
    .description("Security operations aggregate reports")
    .addCommand(
      new Command("remediation-queue")
        .description("Build a sanitized remediation queue across controls, monitors, attack surface, code security, integrations, domains, and pentests")
        .option("--tenant-id <id>", "Tenant id override")
        .option("--json", "Print JSON envelope")
        .action(async (opts: TenantOptions) => {
          await runJsonAction(async () => {
            const config = await requireConfig(opts);
            return buildSecurityRemediationQueue(clientFor(config), tenantIdFor(opts, config));
          }, opts);
        }),
    );
  
  program
    .command("monitors")
    .description("Monitor commands")
    .addCommand(
      new Command("list")
        .option("--tenant-id <id>", "Tenant id override")
        .option("--raw", "Return full upstream monitor rows instead of summarized rows")
        .option("--json", "Print JSON envelope")
        .action(async (opts: TenantOptions & { raw?: boolean }) => {
          await runJsonAction(async () => {
            const config = await requireConfig(opts);
            const data = await clientFor(config).listMonitors(opts.tenantId || config.tenantId);
            return opts.raw ? data : summarizeMonitors(data);
          }, opts);
        }),
    );
  
  program
    .command("controls")
    .description("Control commands")
    .addCommand(
      new Command("list")
        .option("--tenant-id <id>", "Tenant id override")
        .option("--raw", "Return full upstream control rows instead of summarized rows")
        .option("--json", "Print JSON envelope")
        .action(async (opts: TenantOptions & { raw?: boolean }) => {
          await runJsonAction(async () => {
            const config = await requireConfig(opts);
            const data = await clientFor(config).listControls(opts.tenantId || config.tenantId);
            return opts.raw ? data : summarizeControls(data);
          }, opts);
        }),
    );
  
  program
    .command("people")
    .description("People commands")
    .addCommand(
      new Command("list")
        .option("--tenant-id <id>", "Tenant id override")
        .option("--raw", "Return full upstream rows instead of summarized people rows")
        .option("--json", "Print JSON envelope")
        .action(async (opts: TenantOptions & { raw?: boolean }) => {
          await runJsonAction(async () => {
            const config = await requireConfig(opts);
            const data = await clientFor(config).listMembers(opts.tenantId || config.tenantId);
            return opts.raw ? data : summarizeMembers(data);
          }, opts);
        }),
    );
  
  program
    .command("vendors")
    .description("Vendor commands")
    .addCommand(
      new Command("list")
        .option("--tenant-id <id>", "Tenant id override")
        .option("--raw", "Return full upstream vendor rows instead of summarized rows")
        .option("--json", "Print JSON envelope")
        .action(async (opts: TenantOptions & { raw?: boolean }) => {
          await runJsonAction(async () => {
            const config = await requireConfig(opts);
            const data = await clientFor(config).listVendors(opts.tenantId || config.tenantId);
            return opts.raw ? data : summarizeVendors(data);
          }, opts);
        }),
    );
  
  program
    .command("evidence")
    .description("Evidence commands")
    .addCommand(
      new Command("list")
        .option("--tenant-id <id>", "Tenant id override")
        .option("--raw", "Return full upstream evidence rows instead of summarized rows")
        .option("--json", "Print JSON envelope")
        .action(async (opts: TenantOptions & { raw?: boolean }) => {
          await runJsonAction(async () => {
            const config = await requireConfig(opts);
            const data = await clientFor(config).listEvidence(opts.tenantId || config.tenantId);
            return opts.raw ? data : summarizeEvidence(data);
          }, opts);
        }),
    );
  
  program
    .command("policies")
    .description("Policy commands")
    .addCommand(
      new Command("list")
        .option("--tenant-id <id>", "Tenant id override")
        .option("--raw", "Return full upstream policy rows instead of summarized rows")
        .option("--json", "Print JSON envelope")
        .action(async (opts: TenantOptions & { raw?: boolean }) => {
          await runJsonAction(async () => {
            const config = await requireConfig(opts);
            const data = await clientFor(config).listPolicies(opts.tenantId || config.tenantId);
            return opts.raw ? data : summarizePolicies(data);
          }, opts);
        }),
    )
    .addCommand(
      new Command("types")
        .option("--json", "Print JSON envelope")
        .action(async (opts: JsonOptions) => {
          await runJsonAction(async () => clientFor(await requireConfig(opts)).listPolicyTypes(), opts);
        }),
    );
  
  program
    .command("frameworks")
    .description("Compliance framework commands")
    .addCommand(
      new Command("list")
        .option("--tenant-id <id>", "Tenant id override")
        .option("--raw", "Return full upstream framework rows instead of summarized rows")
        .option("--json", "Print JSON envelope")
        .action(async (opts: TenantOptions & { raw?: boolean }) => {
          await runJsonAction(async () => {
            const config = await requireConfig(opts);
            const data = await clientFor(config).listFrameworks(opts.tenantId || config.tenantId);
            return opts.raw ? data : summarizeFrameworks(data);
          }, opts);
        }),
    );
  
  program
    .command("access-reviews")
    .description("Access review commands")
    .addCommand(
      new Command("list")
        .option("--tenant-id <id>", "Tenant id override")
        .option("--raw", "Return full upstream access-review rows instead of summarized rows")
        .option("--json", "Print JSON envelope")
        .action(async (opts: TenantOptions & { raw?: boolean }) => {
          await runJsonAction(async () => {
            const config = await requireConfig(opts);
            const data = await clientFor(config).listAccessReviews(opts.tenantId || config.tenantId);
            return opts.raw ? data : summarizeAccessReviews(data);
          }, opts);
        }),
    );
  
  program
    .command("domains")
    .description("Domain commands")
    .addCommand(
      new Command("list")
        .option("--tenant-id <id>", "Tenant id override")
        .option("--raw", "Return full upstream domain rows instead of summarized rows")
        .option("--json", "Print JSON envelope")
        .action(async (opts: TenantOptions & { raw?: boolean }) => {
          await runJsonAction(async () => {
            const config = await requireConfig(opts);
            const data = await clientFor(config).listDomains(opts.tenantId || config.tenantId);
            return opts.raw ? data : summarizeDomains(data);
          }, opts);
        }),
    );
  
  program
    .command("integrations")
    .description("Integration commands")
    .addCommand(
      new Command("list")
        .option("--tenant-id <id>", "Tenant id override")
        .option("--include-oneleet-managed <value>", "Include Oneleet-managed integrations", "true")
        .option("--raw", "Return full upstream integration rows instead of summarized rows")
        .option("--json", "Print JSON envelope")
        .action(async (opts: TenantOptions & { includeOneleetManaged: string; raw?: boolean }) => {
          await runJsonAction(async () => {
            const config = await requireConfig(opts);
            const data = await clientFor(config).listIntegrations(opts.tenantId || config.tenantId, {
              includeOneleetManaged: opts.includeOneleetManaged,
            });
            return opts.raw ? data : summarizeIntegrations(data);
          }, opts);
        }),
    );
  
  program
    .command("risk-assessments")
    .description("Risk assessment commands")
    .addCommand(
      new Command("list")
        .option("--tenant-id <id>", "Tenant id override")
        .option("--raw", "Return full upstream risk-assessment rows instead of summarized rows")
        .option("--json", "Print JSON envelope")
        .action(async (opts: TenantOptions & { raw?: boolean }) => {
          await runJsonAction(async () => {
            const config = await requireConfig(opts);
            const data = await clientFor(config).listRiskAssessments(opts.tenantId || config.tenantId);
            return opts.raw ? data : summarizeRiskAssessments(data);
          }, opts);
        }),
    );
  
  const training = new Command("security-training").description("Security training commands");
  training
    .command("modules")
    .option("--tenant-id <id>", "Tenant id override")
    .option("--include-drafts", "Include drafts")
    .option("--raw", "Return full upstream module rows instead of summarized rows")
    .option("--json", "Print JSON envelope")
    .action(async (opts: TenantOptions & { includeDrafts?: boolean; raw?: boolean }) => {
      await runJsonAction(async () => {
        const config = await requireConfig(opts);
        const data = await clientFor(config).listSecurityTrainingModules(opts.tenantId || config.tenantId, opts.includeDrafts);
        return opts.raw ? data : summarizeSecurityTrainingModules(data);
      }, opts);
    });
  training
    .command("progress")
    .option("--tenant-id <id>", "Tenant id override")
    .option("--raw", "Return full upstream progress rows instead of summarized rows")
    .option("--json", "Print JSON envelope")
    .action(async (opts: TenantOptions & { raw?: boolean }) => {
      await runJsonAction(async () => {
        const config = await requireConfig(opts);
        const data = await clientFor(config).listSecurityTrainingProgress(opts.tenantId || config.tenantId);
        return opts.raw ? data : summarizeSecurityTrainingProgress(data);
      }, opts);
    });
  program.addCommand(training);
  
  const trust = new Command("trust").description("Trust center commands");
  trust
    .command("readiness")
    .description("Build a sanitized trust-center and customer-security packet readiness report")
    .option("--tenant-id <id>", "Tenant id override")
    .option("--json", "Print JSON envelope")
    .action(async (opts: TenantOptions) => {
      await runJsonAction(async () => {
        const config = await requireConfig(opts);
        return buildTrustReadiness(clientFor(config), tenantIdFor(opts, config));
      }, opts);
    });
  trust
    .command("config")
    .option("--tenant-id <id>", "Tenant id override")
    .option("--raw", "Return full upstream trust config instead of summarized config")
    .option("--json", "Print JSON envelope")
    .action(async (opts: TenantOptions & { raw?: boolean }) => {
      await runJsonAction(async () => {
        const config = await requireConfig(opts);
        const data = await clientFor(config).getTrustConfig(opts.tenantId || config.tenantId);
        return opts.raw ? data : summarizeTrustConfig(data);
      }, opts);
    });
  for (const [name, method] of [
    ["documents", "listTrustDocuments"],
    ["document-requests", "listTrustDocumentRequests"],
    ["faqs", "listTrustFaqs"],
    ["security-issues", "listTrustSecurityIssues"],
  ] as const) {
    trust
      .command(name)
      .option("--tenant-id <id>", "Tenant id override")
      .option("--raw", "Return full upstream rows instead of summarized rows")
      .option("--json", "Print JSON envelope")
      .action(async (opts: TenantOptions & { raw?: boolean }) => {
        await runJsonAction(async () => {
          const config = await requireConfig(opts);
          const data = await clientFor(config)[method](opts.tenantId || config.tenantId);
          return opts.raw ? data : summarizeTrustRows(data);
        }, opts);
      });
  }
  program.addCommand(trust);
  
  program
    .command("reports")
    .description("Report commands")
    .addCommand(
      new Command("list")
        .option("--tenant-id <id>", "Tenant id override")
        .option("--raw", "Return full upstream report rows instead of summarized rows")
        .option("--json", "Print JSON envelope")
        .action(async (opts: TenantOptions & { raw?: boolean }) => {
          await runJsonAction(async () => {
            const config = await requireConfig(opts);
            const data = await clientFor(config).listReports(opts.tenantId || config.tenantId);
            return opts.raw ? data : summarizeReports(data);
          }, opts);
        }),
    );
  
  program
    .command("pentests")
    .description("Pentest commands")
    .addCommand(
      new Command("active-request")
        .option("--tenant-id <id>", "Tenant id override")
        .option("--raw", "Return full upstream active pentest request instead of summarized result")
        .option("--json", "Print JSON envelope")
        .action(async (opts: TenantOptions & { raw?: boolean }) => {
          await runJsonAction(async () => {
            const config = await requireConfig(opts);
            const data = await clientFor(config).getActivePentestRequest(opts.tenantId || config.tenantId);
            return opts.raw ? data : summarizePentestRequest(data);
          }, opts);
        }),
    );
  
  const codeSecurity = new Command("code-security").description("Code security commands");
  codeSecurity
    .command("scan")
    .option("--tenant-id <id>", "Tenant id override")
    .option("--raw", "Return full upstream code-security scan instead of summarized scan")
    .option("--json", "Print JSON envelope")
    .action(async (opts: TenantOptions & { raw?: boolean }) => {
      await runJsonAction(async () => {
        const config = await requireConfig(opts);
        const data = await clientFor(config).getCodeSecurityScan(opts.tenantId || config.tenantId);
        return opts.raw ? data : summarizeCodeScan(data);
      }, opts);
    });
  codeSecurity
    .command("settings")
    .option("--tenant-id <id>", "Tenant id override")
    .option("--json", "Print JSON envelope")
    .action(async (opts: TenantOptions) => {
      await runJsonAction(async () => {
        const config = await requireConfig(opts);
        return clientFor(config).getCodeSecuritySettings(opts.tenantId || config.tenantId);
      }, opts);
    });
  codeSecurity
    .command("repositories")
    .option("--tenant-id <id>", "Tenant id override")
    .option("--raw", "Return full upstream code repository rows instead of summarized rows")
    .option("--json", "Print JSON envelope")
    .action(async (opts: TenantOptions & { raw?: boolean }) => {
      await runJsonAction(async () => {
        const config = await requireConfig(opts);
        const data = await clientFor(config).listGitRepositories(opts.tenantId || config.tenantId);
        return opts.raw ? data : summarizeCodeRepositories(data);
      }, opts);
    });
  program.addCommand(codeSecurity);
  
  const attackSurface = new Command("attack-surface").description("Attack surface commands");
  attackSurface
    .command("summary")
    .option("--tenant-id <id>", "Tenant id override")
    .option("--json", "Print JSON envelope")
    .action(async (opts: TenantOptions) => {
      await runJsonAction(async () => {
        const config = await requireConfig(opts);
        return clientFor(config).getAttackSurfaceStats(opts.tenantId || config.tenantId);
      }, opts);
    });
  attackSurface
    .command("issues")
    .option("--tenant-id <id>", "Tenant id override")
    .option("--limit <n>", "Limit", "50")
    .option("--raw", "Return full upstream issue rows instead of summarized rows")
    .option("--json", "Print JSON envelope")
    .action(async (opts: TenantOptions & { limit: string; raw?: boolean }) => {
      await runJsonAction(async () => {
        const limit = parsePositiveInteger(opts.limit, "--limit");
        const config = await requireConfig(opts);
        const data = await clientFor(config).listAttackSurfaceIssues(opts.tenantId || config.tenantId, { limit });
        return opts.raw ? data : summarizeAttackSurfaceIssues(data);
      }, opts);
    });
  attackSurface
    .command("scans")
    .option("--tenant-id <id>", "Tenant id override")
    .option("--limit <n>", "Limit", "50")
    .option("--raw", "Return full upstream scan rows instead of summarized rows")
    .option("--json", "Print JSON envelope")
    .action(async (opts: TenantOptions & { limit: string; raw?: boolean }) => {
      await runJsonAction(async () => {
        const limit = parsePositiveInteger(opts.limit, "--limit");
        const config = await requireConfig(opts);
        const data = await clientFor(config).listAttackSurfaceScans(opts.tenantId || config.tenantId, { limit });
        return opts.raw ? data : summarizeAttackSurfaceScans(data);
      }, opts);
    });
  program.addCommand(attackSurface);
  
  program
    .command("api")
    .description("Unsafe read-only private API escape hatch")
    .addCommand(
      new Command("get")
        .argument("<path>", "GET path under /api/v1")
        .option("--query <key=value...>", "Query parameter", collect, [])
        .option("--unsafe-raw", "Allow raw private API output; may include sensitive data")
        .option("--json", "Print JSON envelope")
        .action(async (path: string, opts: JsonOptions & { query: string[]; unsafeRaw?: boolean }) => {
          await runJsonAction(async () => {
            if (!opts.unsafeRaw) {
              throw codeError("VALIDATION", "api get returns raw private API payloads. Re-run with --unsafe-raw for local debugging only.");
            }
            const config = await requireConfig(opts);
            return clientFor(config).getRaw(path, parseQueryPairs(opts.query));
          }, opts);
        }),
    );
  
    configureParserContract(program);
  return program;
}
