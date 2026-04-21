import { spawn } from "node:child_process";
import { StringEnum } from "@mariozechner/pi-ai";
import type { ExtensionAPI, ExtensionContext, Theme } from "@mariozechner/pi-coding-agent";
import { Text, truncateToWidth } from "@mariozechner/pi-tui";
import { Type } from "@sinclair/typebox";
import { KevAnalytics } from "./core/analytics.js";
import { mapCveToControls, getControlDetails as getMappedControlDetails, listControls as listMappedControls } from "./core/grc.js";
import { KevStore } from "./core/kev-store.js";
import type {
  AnalyzeCweResult,
  BatchAnalyzeResult,
  ControlDetailsResult,
  ControlMappingResult,
  CveDetails,
  ExploitAvailabilityResult,
  KevSearchResult,
  KevStats,
  ListControlsResult,
  PatchStatusResult,
  RelatedCvesResult,
  SelectedCveState,
  TrendAnalysisResult,
  VendorRiskProfile,
} from "./core/types.js";
import { type BrowserAction, KevBrowserOverlay } from "./ui/browser-overlay.js";

const store = new KevStore();
const analytics = new KevAnalytics(store);

const FrameworkSchema = StringEnum(["nist", "fedramp", "cis"] as const);

const SearchParams = Type.Object({
  query: Type.Optional(Type.String({ description: "Search term matching CVE ID, vendor, product, name, or description" })),
  vendor: Type.Optional(Type.String({ description: "Optional vendor filter" })),
  ransomwareOnly: Type.Optional(Type.Boolean({ description: "Only return CVEs used in ransomware campaigns" })),
  overdueOnly: Type.Optional(Type.Boolean({ description: "Only return overdue CVEs" })),
  limit: Type.Optional(Type.Number({ description: "Maximum number of results to return (default 10)" })),
});

const CveParams = Type.Object({
  cveId: Type.String({ description: "CVE ID, for example CVE-2024-1234" }),
});

const ListParams = Type.Object({
  limit: Type.Optional(Type.Number({ description: "Maximum number of results to return (default 10)" })),
});

const StatsParams = Type.Object({
  topN: Type.Optional(Type.Number({ description: "Number of top vendors and CWEs to return (default 10)" })),
});

const RelatedParams = Type.Object({
  cveId: Type.Optional(Type.String({ description: "Find CVEs related to this CVE ID" })),
  cwe: Type.Optional(Type.String({ description: "Find CVEs with this CWE, for example CWE-79" })),
  vendor: Type.Optional(Type.String({ description: "Find CVEs from this vendor" })),
  product: Type.Optional(Type.String({ description: "Find CVEs affecting this product" })),
  limit: Type.Optional(Type.Number({ description: "Maximum results (default 10)" })),
});

const VendorRiskParams = Type.Object({
  vendor: Type.String({ description: "Vendor name to analyze" }),
});

const BatchAnalyzeParams = Type.Object({
  cveIds: Type.Array(Type.String({ description: "CVE ID" }), { description: "List of CVE IDs to analyze" }),
});

const AnalyzeCweParams = Type.Object({
  cwe: Type.String({ description: "CWE ID to analyze, for example CWE-79" }),
  limit: Type.Optional(Type.Number({ description: "Maximum CVEs to return (default 10)" })),
});

const TrendParams = Type.Object({
  days: Type.Optional(Type.Number({ description: "Number of days to analyze (default 90)" })),
  vendor: Type.Optional(Type.String({ description: "Optional vendor filter" })),
  cwe: Type.Optional(Type.String({ description: "Optional CWE filter" })),
});

const MapControlsParams = Type.Object({
  cveId: Type.String({ description: "CVE ID to map to controls" }),
  framework: Type.Optional(FrameworkSchema),
});

const ControlDetailsParams = Type.Object({
  controlId: Type.String({ description: "Control ID, e.g. SI-2, RA-5, or 7.1" }),
  framework: Type.Optional(FrameworkSchema),
});

const ListControlsParams = Type.Object({
  family: Type.Optional(Type.String({ description: "For NIST/FedRAMP: control family; for CIS: security function" })),
  framework: Type.Optional(FrameworkSchema),
  implementationGroup: Type.Optional(Type.Number({ description: "For CIS only: implementation group 1, 2, or 3" })),
});

function formatPercent(value: number | undefined): string {
  const safe = Math.max(0, value ?? 0);
  return `${Math.round(safe * 100)}%`;
}

function formatDetailsSummary(details: CveDetails): string {
  if (!details.found) return `${details.cveId} not found in the KEV catalog.`;

  const flags = [details.ransomwareUse ? "ransomware" : undefined, details.isOverdue ? "overdue" : undefined]
    .filter(Boolean)
    .join(", ");

  const header = `${details.cveId} — ${details.vendor} / ${details.product}`;
  const epss = `EPSS ${formatPercent(details.epssScore)} (${Math.round((details.epssPercentile ?? 0) * 100)} percentile)`;
  const due = `Due ${details.dueDate ?? "unknown"}`;
  return [header, epss, due, flags || "no special flags"].join(" • ");
}

function renderSearchResults(results: KevSearchResult[]): string {
  if (results.length === 0) return "No KEV matches found.";
  return results
    .map((result) => {
      const flags = [result.ransomwareUse ? "ransomware" : undefined, result.isOverdue ? "overdue" : undefined]
        .filter(Boolean)
        .join(", ");
      return `- ${result.cveId} | ${result.vendor} | ${result.product} | EPSS ${formatPercent(result.epssScore)}${flags ? ` | ${flags}` : ""}`;
    })
    .join("\n");
}

function renderStats(stats: KevStats): string {
  const vendorLines = stats.topVendors.map((item) => `${item.vendor} (${item.count})`).join(", ");
  const cweLines = stats.topCwes.map((item) => `${item.cwe} (${item.count})`).join(", ");
  return [
    `Total KEVs: ${stats.totalCves}`,
    `Ransomware: ${stats.ransomwareCount}`,
    `Overdue: ${stats.overdueCount}`,
    `Top vendors: ${vendorLines || "none"}`,
    `Top CWEs: ${cweLines || "none"}`,
  ].join("\n");
}

function compactSearchList(results: KevSearchResult[], theme: Theme, limit = 5): string {
  const visible = results.slice(0, limit);
  return visible
    .map((item) => `${theme.fg("accent", item.cveId)} ${theme.fg("muted", item.vendor)} ${theme.fg("dim", `EPSS ${formatPercent(item.epssScore)}`)}`)
    .join("\n");
}

type BrowserWorkflowAction = "patch" | "exploit" | "controls" | "related";

interface BrowserHandoff {
  notification: string;
  prompt: string;
}

function buildBrowserHandoff(action: BrowserWorkflowAction, cveId: string, details: CveDetails | null): BrowserHandoff {
  const target = details?.found && details.vendor && details.product ? `${cveId} (${details.vendor} / ${details.product})` : cveId;

  switch (action) {
    case "patch":
      return {
        notification: `Pinned ${cveId} — checking remediation path`,
        prompt:
          `For ${target}, give a remediation-first triage. ` +
          `Run check_patch_status first and summarize in bullets: patch/advisory availability, the best remediation path, and what to do next if patching is delayed or unavailable.`,
      };
    case "exploit":
      return {
        notification: `Pinned ${cveId} — checking exploitability and urgency`,
        prompt:
          `For ${target}, assess urgency. ` +
          `Run check_patch_status first, then check_exploit_availability. Summarize in bullets: exploit signals, patch/advisory status, and immediate next actions.`,
      };
    case "controls":
      return {
        notification: `Pinned ${cveId} — mapping controls`,
        prompt:
          `For ${target}, run map_cve_to_controls and give a concise controls summary. ` +
          `Default to NIST unless another framework is clearly implied, and mention that FedRAMP or CIS mappings are available on request.`,
      };
    case "related":
      return {
        notification: `Pinned ${cveId} — finding related KEVs`,
        prompt:
          `For ${target}, run find_related_cves and summarize the most relevant related KEVs in bullets. ` +
          `Focus on shared vendor, product, or CWE patterns and what they imply for triage.`,
      };
  }
}

type KevinUiMode = "auto" | "on" | "off";

function getBestReferenceUrl(details: CveDetails | null): string | undefined {
  if (!details?.found) return undefined;
  const references = details.references ?? [];
  const patchRef = references.find((ref) => {
    const tags = (ref.tags ?? []).join(" ").toLowerCase();
    const url = ref.url.toLowerCase();
    return tags.includes("patch") || tags.includes("vendor advisory") || url.includes("advisory") || url.includes("security") || url.includes("release-note") || url.includes("support") || url.includes("kb/");
  });
  return patchRef?.url ?? references[0]?.url ?? details.nvdUrl;
}

async function openUrl(url: string): Promise<void> {
  const platform = process.platform;
  const command = platform === "darwin" ? "open" : platform === "win32" ? "cmd" : "xdg-open";
  const args = platform === "darwin" ? [url] : platform === "win32" ? ["/c", "start", "", url] : [url];

  await new Promise<void>((resolve, reject) => {
    const child = spawn(command, args, { stdio: "ignore", detached: true });
    child.on("error", reject);
    child.unref();
    resolve();
  });
}

async function copyToClipboard(text: string): Promise<void> {
  const platform = process.platform;
  const command = platform === "darwin" ? "pbcopy" : platform === "win32" ? "clip" : "xclip";
  const args = platform === "linux" ? ["-selection", "clipboard"] : [];

  await new Promise<void>((resolve, reject) => {
    const child = spawn(command, args, { stdio: ["pipe", "ignore", "ignore"] });
    child.on("error", reject);
    child.on("close", (code) => {
      if (code === 0) resolve();
      else reject(new Error(`${command} exited with code ${code ?? 1}`));
    });
    child.stdin.write(text);
    child.stdin.end();
  });
}

const KEVIN_AUTO_HIDE_MS = 15 * 60 * 1000;

export default function kevinExtension(pi: ExtensionAPI) {
  let selectedCveId: string | null = null;
  let selectedCveDetails: CveDetails | null = null;
  let uiMode: KevinUiMode = "auto";
  let uiSessionActive = false;
  let lastKevinActivityAt = 0;
  let autoHideTimer: ReturnType<typeof setTimeout> | undefined;

  const updateContextWidget = (ctx: ExtensionContext) => {
    const shouldShowWidget = uiMode === "on" || (uiMode === "auto" && uiSessionActive && selectedCveDetails?.found);
    if (!shouldShowWidget) {
      ctx.ui.setWidget("kevin-context", undefined);
      return;
    }

    ctx.ui.setWidget(
      "kevin-context",
      (_tui, theme) => ({
        render(width: number) {
          const lines: string[] = [];
          lines.push(truncateToWidth(theme.fg("borderMuted", "─".repeat(Math.max(10, width))), width));
          lines.push(truncateToWidth(theme.fg("accent", theme.bold(" KEVin context")), width));

          if (!selectedCveDetails || !selectedCveDetails.found) {
            lines.push(truncateToWidth(theme.fg("muted", " No CVE pinned. Use /kev or /cve <id>."), width));
          } else {
            lines.push(truncateToWidth(`${theme.fg("accent", selectedCveDetails.cveId)}  ${theme.fg("text", selectedCveDetails.name ?? "")}`, width));
            lines.push(truncateToWidth(`${theme.fg("text", selectedCveDetails.vendor ?? "")} • ${theme.fg("muted", selectedCveDetails.product ?? "")}`, width));
            lines.push(
              truncateToWidth(
                `${theme.fg("muted", `EPSS ${formatPercent(selectedCveDetails.epssScore)} | Due ${selectedCveDetails.dueDate ?? "—"}`)}${selectedCveDetails.ransomwareUse ? ` ${theme.fg("warning", "| ransomware")}` : ""}${selectedCveDetails.isOverdue ? ` ${theme.fg("error", "| overdue")}` : ""}`,
                width,
              ),
            );
          }

          return lines;
        },
        invalidate() {},
      }),
      { placement: "belowEditor" },
    );
  };

  const refreshSelectedDetails = async () => {
    selectedCveDetails = selectedCveId ? await store.getCveDetails(selectedCveId) : null;
  };

  const clearAutoHideTimer = () => {
    if (autoHideTimer) {
      clearTimeout(autoHideTimer);
      autoHideTimer = undefined;
    }
  };

  const scheduleAutoHide = (ctx: ExtensionContext) => {
    clearAutoHideTimer();
    if (uiMode !== "auto") return;
    autoHideTimer = setTimeout(() => {
      if (Date.now() - lastKevinActivityAt < KEVIN_AUTO_HIDE_MS) return;
      uiSessionActive = false;
      updateContextWidget(ctx);
      ctx.ui.setStatus("kevin", undefined);
    }, KEVIN_AUTO_HIDE_MS);
  };

  const markKevinActivity = (ctx: ExtensionContext) => {
    uiSessionActive = true;
    lastKevinActivityAt = Date.now();
    scheduleAutoHide(ctx);
    updateContextWidget(ctx);
  };

  const persistSelectedCve = (cveId: string | null) => {
    pi.appendEntry("kevin-selected-cve", {
      cveId,
      selectedAt: Date.now(),
    } satisfies SelectedCveState);
  };

  const persistUiMode = (mode: KevinUiMode) => {
    pi.appendEntry("kevin-ui-mode", { mode, savedAt: Date.now() });
  };

  const kevToolNames = new Set([
    "search_kevs",
    "get_cve_details",
    "list_ransomware_cves",
    "list_overdue_cves",
    "get_stats",
    "check_patch_status",
    "check_exploit_availability",
    "map_cve_to_controls",
    "get_control_details",
    "list_controls",
    "find_related_cves",
    "get_vendor_risk_profile",
    "batch_analyze",
    "analyze_cwe",
    "analyze_trends",
  ]);

  const setSelectedCve = async (
    ctx: ExtensionContext,
    cveId: string | null,
    options: {
      persist?: boolean;
      notify?: string | false;
    } = {},
  ) => {
    selectedCveId = cveId;
    if (options.persist ?? true) persistSelectedCve(cveId);
    await refreshSelectedDetails();

    if (cveId) {
      markKevinActivity(ctx);
    } else {
      if (uiMode === "auto") uiSessionActive = false;
      clearAutoHideTimer();
      updateContextWidget(ctx);
    }

    if (options.notify === false) return;

    if (typeof options.notify === "string") {
      ctx.ui.notify(options.notify, "info");
    } else if (cveId && selectedCveDetails?.found) {
      ctx.ui.notify(`Pinned ${selectedCveDetails.cveId}`, "info");
    } else if (!cveId) {
      ctx.ui.notify("Cleared KEVin context", "info");
    }
  };

  const restoreSelectedCve = (ctx: ExtensionContext) => {
    selectedCveId = null;
    uiMode = "auto";
    uiSessionActive = false;
    for (const entry of ctx.sessionManager.getBranch()) {
      if (entry.type === "custom" && entry.customType === "kevin-selected-cve") {
        const data = entry.data as SelectedCveState | undefined;
        selectedCveId = data?.cveId ?? null;
      }
      if (entry.type === "custom" && entry.customType === "kevin-ui-mode") {
        const data = entry.data as { mode?: KevinUiMode } | undefined;
        if (data?.mode === "auto" || data?.mode === "on" || data?.mode === "off") {
          uiMode = data.mode;
        }
      }
    }
    uiSessionActive = uiMode === "on" || Boolean(selectedCveId);
  };

  pi.on("session_start", async (_event, ctx) => {
    restoreSelectedCve(ctx);
    await refreshSelectedDetails();
    updateContextWidget(ctx);
    if (uiSessionActive) {
      lastKevinActivityAt = Date.now();
      scheduleAutoHide(ctx);
    }
  });

  pi.on("session_tree", async (_event, ctx) => {
    restoreSelectedCve(ctx);
    await refreshSelectedDetails();
    updateContextWidget(ctx);
    if (uiSessionActive) {
      lastKevinActivityAt = Date.now();
      scheduleAutoHide(ctx);
    }
  });

  pi.on("before_agent_start", async (event) => {
    if (!selectedCveId) return;
    const details = await store.getCveDetails(selectedCveId);
    if (!details.found) return;

    return {
      systemPrompt: `${event.systemPrompt}\n\nCurrent KEVin context:\n- Active CVE: ${details.cveId}\n- Vendor: ${details.vendor}\n- Product: ${details.product}\n- EPSS: ${formatPercent(details.epssScore)}\n- Due date: ${details.dueDate ?? "unknown"}\n- Ransomware: ${details.ransomwareUse ? "yes" : "no"}\n- Overdue: ${details.isOverdue ? "yes" : "no"}\n\nWhen the user says \"this\", \"it\", or asks for remediation without naming a CVE, assume they mean the active CVE above. Prefer practical remediation guidance using patch status and exploit availability before broader discussion.`,
    };
  });

  pi.on("tool_call", async (event, ctx) => {
    if (!kevToolNames.has(event.toolName)) return;
    markKevinActivity(ctx);
  });

  pi.registerCommand("kev", {
    description: "Open the KEV browser. Optional args prefill the query.",
    handler: async (args, ctx) => {
      if (!ctx.hasUI) {
        ctx.ui.notify("/kev requires interactive mode", "error");
        return;
      }

      const query = args?.trim() ?? "";
      markKevinActivity(ctx);
      ctx.ui.notify("Opening KEV browser…", "info");
      const [results, stats] = await Promise.all([
        store.search({ query: query || undefined, limit: 5000 }),
        store.getStats(8),
      ]);

      const selected = await ctx.ui.custom<BrowserAction | null>(
        (tui, theme, _kb, done) =>
          new KevBrowserOverlay(theme, {
            title: "KEVin Browser",
            initialQuery: query,
            initialSelectedCveId: selectedCveId,
            results,
            stats,
            loadDetails: (cveId) => store.getCveDetails(cveId),
            requestRender: () => tui.requestRender(),
            onSelect: done,
            onCancel: () => done(null),
          }),
        {
          overlay: true,
          overlayOptions: {
            anchor: "center",
            width: "86%",
            maxHeight: "88%",
            margin: 1,
          },
        },
      );

      if (selected) {
        const workflowActions = new Set<BrowserWorkflowAction>(["patch", "exploit", "controls", "related"]);
        const actionableActions = new Set<BrowserAction["action"]>(["open-nvd", "open-ref", "copy-link"]);
        const notification = workflowActions.has(selected.action as BrowserWorkflowAction)
          ? selected.action === "patch"
            ? `Pinned ${selected.cveId} — checking remediation path`
            : selected.action === "exploit"
              ? `Pinned ${selected.cveId} — checking exploitability and urgency`
              : selected.action === "controls"
                ? `Pinned ${selected.cveId} — mapping controls`
                : `Pinned ${selected.cveId} — finding related KEVs`
          : selected.action === "open-nvd"
            ? `Pinned ${selected.cveId} — opening NVD`
            : selected.action === "open-ref"
              ? `Pinned ${selected.cveId} — opening top reference`
              : selected.action === "copy-link"
                ? `Pinned ${selected.cveId} — copying best link`
                : undefined;

        await setSelectedCve(ctx, selected.cveId, { notify: notification });

        if (workflowActions.has(selected.action as BrowserWorkflowAction)) {
          const handoff = buildBrowserHandoff(selected.action as BrowserWorkflowAction, selected.cveId, selectedCveDetails);
          pi.sendUserMessage(handoff.prompt);
        } else if (actionableActions.has(selected.action)) {
          try {
            if (selected.action === "open-nvd") {
              const url = selectedCveDetails?.nvdUrl;
              if (!url) throw new Error("No NVD URL available for this CVE yet");
              await openUrl(url);
              ctx.ui.notify(`Opened NVD for ${selected.cveId}`, "info");
            } else if (selected.action === "open-ref") {
              const url = getBestReferenceUrl(selectedCveDetails);
              if (!url) throw new Error("No advisory or reference link available for this CVE yet");
              await openUrl(url);
              ctx.ui.notify(`Opened top reference for ${selected.cveId}`, "info");
            } else if (selected.action === "copy-link") {
              const url = getBestReferenceUrl(selectedCveDetails) ?? selectedCveDetails?.nvdUrl;
              if (!url) throw new Error("No link available for this CVE yet");
              await copyToClipboard(url);
              ctx.ui.notify(`Copied link for ${selected.cveId}`, "info");
            }
          } catch (error) {
            ctx.ui.notify(error instanceof Error ? error.message : String(error), "error");
          }
        }
      }
    },
  });

  pi.registerCommand("cve", {
    description: "Pin the current CVE context: /cve CVE-2024-1234",
    handler: async (args, ctx) => {
      const cveId = args?.trim().toUpperCase();
      if (!cveId) {
        if (!selectedCveId) {
          ctx.ui.notify("No KEVin context pinned", "info");
          return;
        }
        markKevinActivity(ctx);
        const details = await store.getCveDetails(selectedCveId);
        ctx.ui.notify(formatDetailsSummary(details), "info");
        return;
      }

      const details = await store.getCveDetails(cveId);
      if (!details.found) {
        ctx.ui.notify(`${cveId} is not in the KEV catalog`, "warning");
        return;
      }

      await setSelectedCve(ctx, cveId);
    },
  });

  pi.registerCommand("kev-clear", {
    description: "Clear the pinned KEV context",
    handler: async (_args, ctx) => {
      await setSelectedCve(ctx, null);
    },
  });

  pi.registerCommand("kev-ui", {
    description: "Control KEVin UI chrome: /kev-ui auto|on|off",
    handler: async (args, ctx) => {
      const nextMode = args?.trim().toLowerCase();
      if (!nextMode) {
        ctx.ui.notify(`KEVin UI mode: ${uiMode}`, "info");
        return;
      }
      if (nextMode !== "auto" && nextMode !== "on" && nextMode !== "off") {
        ctx.ui.notify("Usage: /kev-ui auto|on|off", "warning");
        return;
      }

      uiMode = nextMode;
      if (uiMode === "on") {
        uiSessionActive = true;
        lastKevinActivityAt = Date.now();
        scheduleAutoHide(ctx);
      } else if (uiMode === "off") {
        uiSessionActive = false;
        clearAutoHideTimer();
        ctx.ui.setStatus("kevin", undefined);
      } else if (selectedCveId) {
        uiSessionActive = true;
        lastKevinActivityAt = Date.now();
        scheduleAutoHide(ctx);
      }
      persistUiMode(uiMode);
      updateContextWidget(ctx);
      ctx.ui.notify(`KEVin UI mode set to ${uiMode}`, "info");
    },
  });

  pi.registerTool({
    name: "search_kevs",
    label: "Search KEVs",
    description: "Search the CISA Known Exploited Vulnerabilities catalog by CVE, vendor, product, name, or description.",
    promptSnippet: "Search the KEV catalog by CVE, vendor, product, name, or description",
    promptGuidelines: [
      "Use search_kevs immediately when the user names a vendor, product, or broad vulnerability topic.",
      "Use get_cve_details after search_kevs when you need full details on one specific CVE.",
    ],
    parameters: SearchParams,
    async execute(_toolCallId, params) {
      const results = await store.search(params);
      return {
        content: [{ type: "text", text: renderSearchResults(results) }],
        details: { count: results.length, results },
      };
    },
    renderCall(args, theme) {
      const suffix = [args.query, args.vendor ? `vendor:${args.vendor}` : undefined].filter(Boolean).join(" ");
      return new Text(theme.fg("toolTitle", theme.bold("search_kevs ")) + theme.fg("muted", suffix || "catalog"), 0, 0);
    },
    renderResult(result, options, theme) {
      const details = result.details as { count: number; results: KevSearchResult[] } | undefined;
      if (!details) return new Text("No results", 0, 0);
      let text = theme.fg("success", `${details.count} KEV match(es)`);
      if (details.results.length) text += `\n${compactSearchList(options.expanded ? details.results : details.results.slice(0, 5), theme, options.expanded ? details.results.length : 5)}`;
      return new Text(text, 0, 0);
    },
  });

  pi.registerTool({
    name: "get_cve_details",
    label: "CVE Details",
    description: "Get detailed KEV, EPSS, CVSS, and reference information for a specific CVE.",
    promptSnippet: "Fetch full KEV and NVD details for a specific CVE",
    promptGuidelines: ["Use get_cve_details when the user names a specific CVE or after narrowing down search results."],
    parameters: CveParams,
    async execute(_toolCallId, params) {
      const details = await store.getCveDetails(params.cveId);
      return {
        content: [{ type: "text", text: formatDetailsSummary(details) }],
        details,
      };
    },
    renderCall(args, theme) {
      return new Text(theme.fg("toolTitle", theme.bold("get_cve_details ")) + theme.fg("accent", args.cveId), 0, 0);
    },
    renderResult(result, options, theme) {
      const details = result.details as CveDetails | undefined;
      if (!details) return new Text("No details", 0, 0);
      if (!details.found) return new Text(theme.fg("warning", `${details.cveId} not found`), 0, 0);
      let text = `${theme.fg("accent", details.cveId)} ${theme.fg("muted", details.vendor ?? "")} ${theme.fg("dim", `EPSS ${formatPercent(details.epssScore)}`)}`;
      if (options.expanded) {
        text += `\n${theme.fg("text", details.name ?? "")}`;
        text += `\n${theme.fg("muted", details.description ?? "")}`;
        if (details.requiredAction) text += `\n${theme.fg("warning", `Action: ${details.requiredAction}`)}`;
      }
      return new Text(text, 0, 0);
    },
  });

  pi.registerTool({
    name: "list_ransomware_cves",
    label: "Ransomware KEVs",
    description: "List KEV entries with known ransomware campaign use.",
    parameters: ListParams,
    async execute(_toolCallId, params) {
      const results = await store.listRansomware(params.limit);
      return {
        content: [{ type: "text", text: renderSearchResults(results) }],
        details: { count: results.length, results },
      };
    },
  });

  pi.registerTool({
    name: "list_overdue_cves",
    label: "Overdue KEVs",
    description: "List KEV entries that are past the remediation due date.",
    parameters: ListParams,
    async execute(_toolCallId, params) {
      const results = await store.listOverdue(params.limit);
      return {
        content: [{ type: "text", text: renderSearchResults(results) }],
        details: { count: results.length, results },
      };
    },
  });

  pi.registerTool({
    name: "get_stats",
    label: "KEV Stats",
    description: "Get summary statistics for the KEV catalog, including top vendors and CWEs.",
    parameters: StatsParams,
    async execute(_toolCallId, params) {
      const stats = await store.getStats(params.topN);
      return {
        content: [{ type: "text", text: renderStats(stats) }],
        details: stats,
      };
    },
    renderCall(_args, theme) {
      return new Text(theme.fg("toolTitle", theme.bold("get_stats")), 0, 0);
    },
    renderResult(result, options, theme) {
      const stats = result.details as KevStats | undefined;
      if (!stats) return new Text("No stats", 0, 0);
      let text = theme.fg("success", `${stats.totalCves} KEVs`) + theme.fg("muted", ` • ${stats.ransomwareCount} ransomware • ${stats.overdueCount} overdue`);
      if (options.expanded) text += `\n${theme.fg("dim", `Top vendors: ${stats.topVendors.map((item) => `${item.vendor} (${item.count})`).join(", ")}`)}`;
      return new Text(text, 0, 0);
    },
  });

  pi.registerTool({
    name: "check_patch_status",
    label: "Patch Status",
    description: "Check for patch and advisory references for a specific CVE using NVD references.",
    promptSnippet: "Check whether a CVE has patch or vendor advisory references",
    promptGuidelines: ["Use check_patch_status first when the user asks how to fix or remediate a vulnerability."],
    parameters: CveParams,
    async execute(_toolCallId, params) {
      const patchStatus = await store.getPatchStatus(params.cveId);
      const summary = patchStatus.hasPatch ? `${patchStatus.cveId} has ${patchStatus.patchReferences.length} patch/advisory reference(s).` : `${patchStatus.cveId} has no obvious patch references in NVD.`;
      return {
        content: [{ type: "text", text: summary }],
        details: patchStatus,
      };
    },
    renderResult(result, options, theme) {
      const details = result.details as PatchStatusResult | undefined;
      if (!details) return new Text("No patch data", 0, 0);
      let text = details.hasPatch ? theme.fg("success", `${details.cveId} has patch references`) : theme.fg("warning", `${details.cveId} has no clear patch references`);
      if (options.expanded && details.patchReferences.length > 0) text += `\n${details.patchReferences.slice(0, 5).map((ref) => theme.fg("dim", ref.url)).join("\n")}`;
      return new Text(text, 0, 0);
    },
  });

  pi.registerTool({
    name: "check_exploit_availability",
    label: "Exploit Availability",
    description: "Check public exploit signals for a specific CVE from NVD references and provide quick search URLs.",
    promptSnippet: "Check whether a CVE has public exploit signals or exploit references",
    promptGuidelines: ["Use check_exploit_availability after check_patch_status when the user asks how urgent a vulnerability is."],
    parameters: CveParams,
    async execute(_toolCallId, params) {
      const exploitStatus = await store.getExploitAvailability(params.cveId);
      const summary = exploitStatus.hasPublicExploit ? `${exploitStatus.cveId} has public exploit signals: ${exploitStatus.exploitSignals.join(", ")}` : `${exploitStatus.cveId} has no obvious public exploit signals in NVD references.`;
      return {
        content: [{ type: "text", text: summary }],
        details: exploitStatus,
      };
    },
    renderResult(result, options, theme) {
      const details = result.details as ExploitAvailabilityResult | undefined;
      if (!details) return new Text("No exploit data", 0, 0);
      let text = details.hasPublicExploit ? theme.fg("warning", `${details.cveId} has exploit signals`) : theme.fg("success", `${details.cveId} has no obvious exploit signals`);
      if (options.expanded) {
        text += `\n${theme.fg("dim", `Signals: ${details.exploitSignals.join(", ") || "none"}`)}`;
        text += `\n${theme.fg("dim", details.exploitDbSearchUrl)}`;
      }
      return new Text(text, 0, 0);
    },
  });

  pi.registerTool({
    name: "map_cve_to_controls",
    label: "Map Controls",
    description: "Map a KEV CVE to NIST 800-53, FedRAMP, or CIS Controls v8.",
    promptSnippet: "Map a KEV CVE to NIST, FedRAMP, or CIS security controls",
    promptGuidelines: ["Use map_cve_to_controls when the user explicitly asks about controls, NIST, FedRAMP, CIS, or compliance mapping."],
    parameters: MapControlsParams,
    async execute(_toolCallId, params) {
      const details = await store.getCveDetails(params.cveId);
      const mapping = mapCveToControls(details, params.framework);
      const count = mapping.controls?.length ?? mapping.cisControls?.length ?? 0;
      return {
        content: [{ type: "text", text: mapping.found ? `${mapping.cveId} maps to ${count} ${mapping.framework.toUpperCase()} control(s).` : mapping.rationale }],
        details: mapping,
      };
    },
    renderResult(result, options, theme) {
      const details = result.details as ControlMappingResult | undefined;
      if (!details) return new Text("No mapping", 0, 0);
      if (!details.found) return new Text(theme.fg("warning", details.rationale), 0, 0);
      const controls = details.controls?.map((item) => item.id) ?? details.cisControls?.map((item) => item.id) ?? [];
      let text = theme.fg("success", `${details.framework.toUpperCase()} mapping: ${controls.join(", ")}`);
      if (options.expanded) text += `\n${theme.fg("dim", details.rationale)}`;
      return new Text(text, 0, 0);
    },
  });

  pi.registerTool({
    name: "get_control_details",
    label: "Control Details",
    description: "Get details about a NIST, FedRAMP, or CIS control.",
    parameters: ControlDetailsParams,
    async execute(_toolCallId, params) {
      const details = getMappedControlDetails(params.controlId, params.framework);
      const summary = !details.found
        ? `Control ${params.controlId} not found.`
        : details.control
          ? `${details.control.id} — ${details.control.name}`
          : `${details.cisControl?.id} — ${details.cisControl?.title}`;
      return {
        content: [{ type: "text", text: summary }],
        details,
      };
    },
    renderResult(result, options, theme) {
      const details = result.details as ControlDetailsResult | undefined;
      if (!details) return new Text("No control details", 0, 0);
      if (!details.found) return new Text(theme.fg("warning", "Control not found"), 0, 0);
      const title = details.control ? `${details.control.id} ${details.control.name}` : `${details.cisControl?.id} ${details.cisControl?.title}`;
      let text = theme.fg("accent", title);
      if (options.expanded) text += `\n${theme.fg("muted", details.control?.description ?? details.cisControl?.description ?? "")}`;
      return new Text(text, 0, 0);
    },
  });

  pi.registerTool({
    name: "list_controls",
    label: "List Controls",
    description: "List NIST, FedRAMP, or CIS controls with optional filtering.",
    parameters: ListControlsParams,
    async execute(_toolCallId, params) {
      const details = listMappedControls(params);
      const controls = details.controls?.map((item) => item.id) ?? details.cisControls?.map((item) => item.id) ?? [];
      return {
        content: [{ type: "text", text: controls.length ? controls.join(", ") : "No controls found." }],
        details,
      };
    },
    renderResult(result, options, theme) {
      const details = result.details as ListControlsResult | undefined;
      if (!details) return new Text("No controls", 0, 0);
      const controls = details.controls?.map((item) => item.id) ?? details.cisControls?.map((item) => item.id) ?? [];
      let text = theme.fg("success", `${details.count} control(s)`);
      if (controls.length) text += `\n${theme.fg("dim", (options.expanded ? controls : controls.slice(0, 12)).join(", "))}`;
      return new Text(text, 0, 0);
    },
  });

  pi.registerTool({
    name: "find_related_cves",
    label: "Related CVEs",
    description: "Find CVEs related by CWE, vendor, product, or source CVE.",
    parameters: RelatedParams,
    async execute(_toolCallId, params) {
      const details = await analytics.findRelatedCves(params);
      return {
        content: [{ type: "text", text: details.relatedCves.length ? details.relatedCves.map((item) => `- ${item.cveId} | ${item.similarity}`).join("\n") : "No related CVEs found." }],
        details,
      };
    },
    renderResult(result, options, theme) {
      const details = result.details as RelatedCvesResult | undefined;
      if (!details) return new Text("No related CVEs", 0, 0);
      let text = theme.fg("success", `${details.count} related CVE(s)`);
      if (details.relatedCves.length) text += `\n${compactSearchList((options.expanded ? details.relatedCves : details.relatedCves.slice(0, 5)).map((item) => ({ cveId: item.cveId, vendor: item.vendor, product: item.product, name: item.name, dateAdded: undefined, dueDate: undefined, ransomwareUse: item.ransomwareUse, isOverdue: item.isOverdue, epssScore: item.epssScore, epssPercentile: 0, shortDescription: item.similarity })), theme, options.expanded ? details.relatedCves.length : 5)}`;
      return new Text(text, 0, 0);
    },
  });

  pi.registerTool({
    name: "get_vendor_risk_profile",
    label: "Vendor Risk",
    description: "Get a KEV risk profile for a vendor.",
    parameters: VendorRiskParams,
    async execute(_toolCallId, params) {
      const details = await analytics.getVendorRiskProfile(params.vendor);
      const summary = details.found
        ? `${details.vendor}: ${details.totalCves} KEVs, risk ${details.riskLevel}, avg EPSS ${formatPercent(details.averageEpss)}`
        : `${details.vendor}: no KEVs found.`;
      return {
        content: [{ type: "text", text: summary }],
        details,
      };
    },
    renderResult(result, options, theme) {
      const details = result.details as VendorRiskProfile | undefined;
      if (!details) return new Text("No vendor profile", 0, 0);
      if (!details.found) return new Text(theme.fg("warning", `${details.vendor}: no KEVs found`), 0, 0);
      let text = theme.fg("accent", `${details.vendor} ${details.riskLevel}`) + theme.fg("muted", ` • ${details.totalCves} CVEs • avg EPSS ${formatPercent(details.averageEpss)}`);
      if (options.expanded && details.topProducts?.length) text += `\n${theme.fg("dim", `Top products: ${details.topProducts.map((item) => `${item.product} (${item.cveCount})`).join(", ")}`)}`;
      return new Text(text, 0, 0);
    },
  });

  pi.registerTool({
    name: "batch_analyze",
    label: "Batch Analyze",
    description: "Analyze multiple CVEs at once and prioritize them.",
    parameters: BatchAnalyzeParams,
    async execute(_toolCallId, params) {
      const details = await analytics.batchAnalyze(params.cveIds);
      return {
        content: [{ type: "text", text: `${details.found}/${details.count} CVEs found. Critical: ${details.summary.criticalPriority}, High: ${details.summary.highPriority}.` }],
        details,
      };
    },
    renderResult(result, options, theme) {
      const details = result.details as BatchAnalyzeResult | undefined;
      if (!details) return new Text("No batch analysis", 0, 0);
      let text = theme.fg("success", `${details.found}/${details.count} analyzed`) + theme.fg("muted", ` • critical ${details.summary.criticalPriority} • high ${details.summary.highPriority}`);
      if (options.expanded) text += `\n${theme.fg("dim", details.cves.filter((item) => item.found).slice(0, 8).map((item) => `${item.cveId}:${item.riskPriority}`).join(", "))}`;
      return new Text(text, 0, 0);
    },
  });

  pi.registerTool({
    name: "analyze_cwe",
    label: "Analyze CWE",
    description: "Analyze a CWE across the KEV catalog and suggest mitigations.",
    parameters: AnalyzeCweParams,
    async execute(_toolCallId, params) {
      const details = await analytics.analyzeCwe(params.cwe, params.limit);
      const summary = details.found
        ? `${details.cwe}: ${details.totalCves} KEV CVEs, avg EPSS ${formatPercent(details.averageEpss)}`
        : `${details.cwe}: no KEVs found.`;
      return {
        content: [{ type: "text", text: summary }],
        details,
      };
    },
    renderResult(result, options, theme) {
      const details = result.details as AnalyzeCweResult | undefined;
      if (!details) return new Text("No CWE analysis", 0, 0);
      if (!details.found) return new Text(theme.fg("warning", `${details.cwe}: no KEVs found`), 0, 0);
      let text = theme.fg("accent", `${details.cwe} ${details.cweName ?? ""}`) + theme.fg("muted", ` • ${details.totalCves} CVEs • avg EPSS ${formatPercent(details.averageEpss)}`);
      if (options.expanded && details.mitigations?.length) text += `\n${theme.fg("dim", `Mitigations: ${details.mitigations.join(", ")}`)}`;
      return new Text(text, 0, 0);
    },
  });

  pi.registerTool({
    name: "analyze_trends",
    label: "Analyze Trends",
    description: "Analyze recent KEV trends over time by vendor or CWE.",
    parameters: TrendParams,
    async execute(_toolCallId, params) {
      const details = await analytics.analyzeTrends(params);
      return {
        content: [{ type: "text", text: `${details.period}: ${details.totalCves} KEVs, trend ${details.riskTrend}` }],
        details,
      };
    },
    renderResult(result, options, theme) {
      const details = result.details as TrendAnalysisResult | undefined;
      if (!details) return new Text("No trend analysis", 0, 0);
      let text = theme.fg("accent", `${details.period}`) + theme.fg("muted", ` • ${details.totalCves} CVEs • ${details.riskTrend}`);
      if (options.expanded && details.topVendors.length) text += `\n${theme.fg("dim", `Top vendors: ${details.topVendors.slice(0, 5).map((item) => `${item.vendor} (${item.count})`).join(", ")}`)}`;
      return new Text(text, 0, 0);
    },
  });
}
