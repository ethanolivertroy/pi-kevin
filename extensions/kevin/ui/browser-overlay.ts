import type { Theme } from "@mariozechner/pi-coding-agent";
import { Key, matchesKey, truncateToWidth, visibleWidth, wrapTextWithAnsi } from "@mariozechner/pi-tui";
import type { CveDetails, KevSearchResult, KevStats, PatchReference } from "../core/types.js";

export interface BrowserAction {
  action: "pin" | "patch" | "exploit" | "controls" | "related" | "open-nvd" | "open-ref" | "copy-link";
  cveId: string;
}

interface BrowserOptions {
  title?: string;
  initialQuery?: string;
  initialSelectedCveId?: string | null;
  results: KevSearchResult[];
  stats?: KevStats;
  loadDetails?: (cveId: string) => Promise<CveDetails>;
  requestRender?: () => void;
  onSelect: (action: BrowserAction) => void;
  onCancel: () => void;
}

type SortMode = "best" | "recent" | "epss" | "vendor";
type DetailMode = "preview" | "detail";

function isPrintableCharacter(data: string): boolean {
  return data.length === 1 && data >= " " && data !== "\u007f";
}

function formatPercent(value: number): string {
  return `${Math.round(value * 100)}%`;
}

function padRightAnsi(text: string, width: number): string {
  const remaining = Math.max(0, width - visibleWidth(text));
  return text + " ".repeat(remaining);
}

function joinColumns(left: string, right: string, leftWidth: number, rightWidth: number): string {
  return `${padRightAnsi(truncateToWidth(left, leftWidth), leftWidth)} ${truncateToWidth(right, rightWidth)}`;
}

function epssBar(theme: Theme, score: number, width: number): string {
  const filled = Math.max(0, Math.min(width, Math.round(score * width)));
  const empty = Math.max(0, width - filled);
  const fillColor = score >= 0.7 ? "error" : score >= 0.3 ? "warning" : "success";
  return `${theme.fg(fillColor, "█".repeat(filled))}${theme.fg("muted", "░".repeat(empty))}`;
}

function riskColor(theme: Theme, score: number): string {
  if (score >= 0.7) return theme.fg("error", formatPercent(score));
  if (score >= 0.3) return theme.fg("warning", formatPercent(score));
  return theme.fg("success", formatPercent(score));
}

function epssBadge(theme: Theme, score: number): string {
  if (score >= 0.7) return theme.fg("error", "HIGH");
  if (score >= 0.3) return theme.fg("warning", "MED");
  return theme.fg("success", "LOW");
}

function badges(theme: Theme, result: KevSearchResult | CveDetails): string[] {
  const output: string[] = [];
  if (result.ransomwareUse) output.push(theme.fg("warning", "RANSOMWARE"));
  if (result.isOverdue) output.push(theme.fg("error", "OVERDUE"));
  const score = "epssScore" in result ? (result.epssScore ?? 0) : 0;
  if (score > 0) output.push(theme.fg(score >= 0.7 ? "error" : score >= 0.3 ? "warning" : "success", `EPSS ${epssBadge(theme, score)}`));
  return output;
}

function selectedRow(theme: Theme, text: string, width: number): string {
  return theme.bg("selectedBg", padRightAnsi(truncateToWidth(text, width), width));
}

function summarizeUrl(url: string): string {
  try {
    const parsed = new URL(url);
    return `${parsed.hostname}${parsed.pathname}`;
  } catch {
    return url.replace(/^https?:\/\//, "");
  }
}

function isPatchReference(ref: PatchReference): boolean {
  const tags = (ref.tags ?? []).join(" ").toLowerCase();
  const url = ref.url.toLowerCase();
  return tags.includes("patch") || tags.includes("vendor advisory") || url.includes("advisory") || url.includes("security") || url.includes("release-note") || url.includes("support") || url.includes("kb/");
}

function referenceLine(theme: Theme, ref: PatchReference): string {
  const tags = (ref.tags ?? []).slice(0, 2).join(", ");
  return `${theme.fg("text", summarizeUrl(ref.url))}${tags ? ` ${theme.fg("muted", `[${tags}]`)}` : ""}`;
}

function fitPaneLines(lines: string[], width: number, height: number): string[] {
  const fitted = lines.slice(0, height).map((line) => truncateToWidth(line, width));
  while (fitted.length < height) fitted.push("");
  return fitted;
}

function actionHintLine(theme: Theme): string {
  return theme.fg("muted", "Enter pin • Ctrl+P patch • Ctrl+E urgency • Ctrl+G controls • Ctrl+L related");
}

function linkHintLine(theme: Theme): string {
  return theme.fg("muted", "Ctrl+N NVD • Ctrl+V top patch/ref • Ctrl+Y copy best link • Esc close");
}

function sortLabel(mode: SortMode): string {
  switch (mode) {
    case "best":
      return "best";
    case "recent":
      return "recent";
    case "epss":
      return "epss";
    case "vendor":
      return "vendor";
  }
}

export class KevBrowserOverlay {
  private readonly theme: Theme;
  private readonly options: BrowserOptions;
  private readonly allResults: KevSearchResult[];
  private query: string;
  private filtered: KevSearchResult[];
  private selectedIndex = 0;
  private scrollOffset = 0;
  private sortMode: SortMode = "best";
  private ransomwareOnly = false;
  private overdueOnly = false;
  private detailMode: DetailMode = "preview";
  private selectedDetails?: CveDetails;
  private loadingDetails = false;
  private cachedWidth?: number;
  private cachedLines?: string[];

  constructor(theme: Theme, options: BrowserOptions) {
    this.theme = theme;
    this.options = options;
    this.allResults = options.results;
    this.query = options.initialQuery ?? "";
    this.filtered = this.applyFilter(this.query);
    if (options.initialSelectedCveId) {
      const index = this.filtered.findIndex((item) => item.cveId === options.initialSelectedCveId);
      if (index >= 0) this.selectedIndex = index;
    }
    void this.loadSelectedDetails();
  }

  handleInput(data: string): void {
    if (matchesKey(data, Key.escape)) {
      this.options.onCancel();
      return;
    }

    if (matchesKey(data, Key.enter)) {
      const selected = this.getSelected();
      if (selected) this.options.onSelect({ action: "pin", cveId: selected.cveId });
      return;
    }

    if (matchesKey(data, Key.ctrl("p"))) {
      const selected = this.getSelected();
      if (selected) this.options.onSelect({ action: "patch", cveId: selected.cveId });
      return;
    }

    if (matchesKey(data, Key.ctrl("e"))) {
      const selected = this.getSelected();
      if (selected) this.options.onSelect({ action: "exploit", cveId: selected.cveId });
      return;
    }

    if (matchesKey(data, Key.ctrl("g"))) {
      const selected = this.getSelected();
      if (selected) this.options.onSelect({ action: "controls", cveId: selected.cveId });
      return;
    }

    if (matchesKey(data, Key.ctrl("l"))) {
      const selected = this.getSelected();
      if (selected) this.options.onSelect({ action: "related", cveId: selected.cveId });
      return;
    }

    if (matchesKey(data, Key.ctrl("n"))) {
      const selected = this.getSelected();
      if (selected) this.options.onSelect({ action: "open-nvd", cveId: selected.cveId });
      return;
    }

    if (matchesKey(data, Key.ctrl("v"))) {
      const selected = this.getSelected();
      if (selected) this.options.onSelect({ action: "open-ref", cveId: selected.cveId });
      return;
    }

    if (matchesKey(data, Key.ctrl("y"))) {
      const selected = this.getSelected();
      if (selected) this.options.onSelect({ action: "copy-link", cveId: selected.cveId });
      return;
    }

    if (matchesKey(data, Key.backspace)) {
      this.query = this.query.slice(0, -1);
      this.recompute();
      return;
    }

    if (matchesKey(data, Key.ctrl("u"))) {
      this.query = "";
      this.recompute();
      return;
    }

    if (matchesKey(data, Key.ctrl("s"))) {
      this.sortMode = this.sortMode === "best" ? "recent" : this.sortMode === "recent" ? "epss" : this.sortMode === "epss" ? "vendor" : "best";
      this.recompute(false);
      return;
    }

    if (matchesKey(data, Key.ctrl("r"))) {
      this.ransomwareOnly = !this.ransomwareOnly;
      this.recompute();
      return;
    }

    if (matchesKey(data, Key.ctrl("o"))) {
      this.overdueOnly = !this.overdueOnly;
      this.recompute();
      return;
    }

    if (matchesKey(data, Key.tab)) {
      this.detailMode = this.detailMode === "preview" ? "detail" : "preview";
      this.invalidate();
      return;
    }

    if (matchesKey(data, Key.pageDown)) {
      this.selectedIndex = Math.min(this.filtered.length - 1, this.selectedIndex + 8);
      void this.loadSelectedDetails();
      this.invalidate();
      return;
    }

    if (matchesKey(data, Key.pageUp)) {
      this.selectedIndex = Math.max(0, this.selectedIndex - 8);
      void this.loadSelectedDetails();
      this.invalidate();
      return;
    }

    if (matchesKey(data, Key.down)) {
      if (this.selectedIndex < this.filtered.length - 1) this.selectedIndex += 1;
      void this.loadSelectedDetails();
      this.invalidate();
      return;
    }

    if (matchesKey(data, Key.up)) {
      if (this.selectedIndex > 0) this.selectedIndex -= 1;
      void this.loadSelectedDetails();
      this.invalidate();
      return;
    }

    if (matchesKey(data, Key.home)) {
      this.selectedIndex = 0;
      void this.loadSelectedDetails();
      this.invalidate();
      return;
    }

    if (matchesKey(data, Key.end)) {
      this.selectedIndex = Math.max(0, this.filtered.length - 1);
      void this.loadSelectedDetails();
      this.invalidate();
      return;
    }

    if (isPrintableCharacter(data)) {
      this.query += data;
      this.recompute();
    }
  }

  render(width: number): string[] {
    if (this.cachedLines && this.cachedWidth === width) return this.cachedLines;

    const framedWidth = Math.max(24, width - 2);
    const innerLines = this.renderInner(framedWidth);
    const output: string[] = [];

    output.push(`╭${this.theme.fg("borderAccent", "─".repeat(framedWidth))}╮`);
    for (const line of innerLines) {
      output.push(`│${padRightAnsi(truncateToWidth(line, framedWidth), framedWidth)}│`);
    }
    output.push(`╰${this.theme.fg("borderAccent", "─".repeat(framedWidth))}╯`);

    this.cachedWidth = width;
    this.cachedLines = output;
    return output;
  }

  invalidate(): void {
    this.cachedWidth = undefined;
    this.cachedLines = undefined;
    this.options.requestRender?.();
  }

  private renderInner(width: number): string[] {
    const lines: string[] = [];
    const title = this.options.title ?? "KEVin Browser";
    const selected = this.getSelected();
    const leftWidth = Math.max(44, Math.floor(width * 0.56));
    const rightWidth = Math.max(24, width - leftWidth - 1);
    const visibleRows = 8;
    const bodyHeight = visibleRows * 2;
    const start = Math.min(this.scrollOffsetFor(visibleRows), Math.max(0, this.filtered.length - visibleRows));
    const visible = this.filtered.slice(start, start + visibleRows);

    lines.push(truncateToWidth(`${this.theme.fg("accent", "◆")} ${this.theme.fg("accent", this.theme.bold(title))} ${this.theme.fg("muted", "• CISA Known Exploited Vulnerabilities")}`, width));

    if (this.options.stats) {
      lines.push(
        truncateToWidth(
          `${this.theme.fg("accent", `[${this.options.stats.totalCves} KEVs]`)} ${this.theme.fg("warning", `[${this.options.stats.ransomwareCount} ransomware]`)} ${this.theme.fg("error", `[${this.options.stats.overdueCount} overdue]`)}`,
          width,
        ),
      );
    }

    const queryText = this.query ? this.theme.fg("text", this.query) : this.theme.fg("muted", "type to filter by CVE, vendor, product, CWE...");
    lines.push(truncateToWidth(`${this.theme.fg("muted", "⌕ Search:")} ${queryText}`, width));
    lines.push(
      truncateToWidth(
        `${this.theme.fg("muted", "Sort")} ${this.theme.fg("text", sortLabel(this.sortMode))}${this.ransomwareOnly ? this.theme.fg("warning", " • ransomware") : ""}${this.overdueOnly ? this.theme.fg("error", " • overdue") : ""}${this.theme.fg("muted", ` • ${this.detailMode}`)}`,
        width,
      ),
    );
    lines.push(truncateToWidth(this.theme.fg("borderMuted", "─".repeat(Math.max(12, width))), width));

    if (this.detailMode === "detail") {
      const detailLines = this.renderFullDetailPage(selected, width, 16);
      lines.push(truncateToWidth(this.theme.fg("accent", this.theme.bold(" ◆ Detail")), width));
      lines.push(...detailLines);
      lines.push(truncateToWidth(this.theme.fg("borderMuted", "─".repeat(Math.max(12, width))), width));
      lines.push(truncateToWidth(this.theme.fg("muted", `${this.filtered.length} result(s) • ${selected ? `selected ${selected.cveId}` : "no selection"}`), width));
      lines.push(truncateToWidth(this.theme.fg("muted", "↑↓ move • Tab back to split preview • Ctrl+N NVD • Ctrl+V top ref • Ctrl+Y copy link • Esc close"), width));
      return lines;
    }

    const resultLines = this.renderResultLines(visible, start, leftWidth, visibleRows);
    const previewLines = selected
      ? this.renderPreviewLines(selected, this.selectedDetails?.found && this.selectedDetails.cveId === selected.cveId ? this.selectedDetails : undefined, rightWidth, bodyHeight)
      : fitPaneLines([this.theme.fg("muted", " Select a KEV to preview.")], rightWidth, bodyHeight);

    lines.push(joinColumns(this.theme.fg("accent", this.theme.bold(" ◆ Results")), this.theme.fg("accent", this.theme.bold(" ◆ Preview")), leftWidth, rightWidth));

    for (let row = 0; row < bodyHeight; row++) {
      lines.push(joinColumns(resultLines[row] ?? "", previewLines[row] ?? "", leftWidth, rightWidth));
    }

    lines.push(truncateToWidth(this.theme.fg("borderMuted", "─".repeat(Math.max(12, width))), width));
    lines.push(
      truncateToWidth(
        `${this.theme.fg("muted", `${this.filtered.length} result(s)`)}${selected ? this.theme.fg("muted", ` • selected ${selected.cveId}`) : ""}${this.filtered.length > visibleRows ? this.theme.fg("muted", ` • showing ${start + 1}-${Math.min(start + visibleRows, this.filtered.length)}`) : ""}`,
        width,
      ),
    );
    lines.push(truncateToWidth(this.theme.fg("muted", "type to search • ↑↓ move • PgUp/PgDn jump • Ctrl+S sort • Ctrl+R ransomware • Ctrl+O overdue"), width));
    lines.push(truncateToWidth(this.theme.fg("muted", "Enter pin • Tab full detail • Ctrl+P patch • Ctrl+E exploit • Ctrl+G controls • Ctrl+L related • Esc close"), width));
    return lines;
  }

  private recompute(resetSelection = true): void {
    this.filtered = this.applyFilter(this.query);
    if (resetSelection) {
      this.selectedIndex = 0;
      this.scrollOffset = 0;
    } else {
      this.selectedIndex = Math.min(this.selectedIndex, Math.max(0, this.filtered.length - 1));
    }
    void this.loadSelectedDetails();
    this.invalidate();
  }

  private applyFilter(query: string): KevSearchResult[] {
    const q = query.trim().toLowerCase();
    const filtered = this.allResults.filter((item) => {
      if (this.ransomwareOnly && !item.ransomwareUse) return false;
      if (this.overdueOnly && !item.isOverdue) return false;
      return true;
    });

    if (!q) {
      return filtered.slice().sort((a, b) => this.compare(a, b, 1, 1));
    }

    return filtered
      .map((item) => ({ item, score: this.score(item, q) }))
      .filter((entry) => entry.score > 0)
      .sort((a, b) => this.compare(a.item, b.item, a.score, b.score))
      .map((entry) => entry.item);
  }

  private compare(a: KevSearchResult, b: KevSearchResult, aScore: number, bScore: number): number {
    switch (this.sortMode) {
      case "epss":
        return b.epssScore - a.epssScore || (b.dateAdded ?? "").localeCompare(a.dateAdded ?? "");
      case "vendor":
        return a.vendor.localeCompare(b.vendor) || (b.dateAdded ?? "").localeCompare(a.dateAdded ?? "");
      case "recent":
        return (b.dateAdded ?? "").localeCompare(a.dateAdded ?? "");
      case "best":
      default:
        return bScore - aScore || b.epssScore - a.epssScore || (b.dateAdded ?? "").localeCompare(a.dateAdded ?? "");
    }
  }

  private score(item: KevSearchResult, query: string): number {
    const cve = item.cveId.toLowerCase();
    const vendor = item.vendor.toLowerCase();
    const product = item.product.toLowerCase();
    const name = item.name.toLowerCase();
    const desc = item.shortDescription.toLowerCase();
    if (cve === query) return 200;
    if (cve.startsWith(query)) return 160;
    if (vendor === query) return 130;
    if (product === query) return 120;
    if (name.includes(query)) return 100;
    if (vendor.includes(query)) return 90;
    if (product.includes(query)) return 80;
    if (desc.includes(query)) return 50;
    return 0;
  }

  private getSelected(): KevSearchResult | undefined {
    return this.filtered[this.selectedIndex];
  }

  private async loadSelectedDetails(): Promise<void> {
    const selected = this.getSelected();
    if (!selected || !this.options.loadDetails) {
      this.selectedDetails = undefined;
      this.loadingDetails = false;
      return;
    }

    this.loadingDetails = true;
    const cveId = selected.cveId;
    this.invalidate();
    try {
      const details = await this.options.loadDetails(cveId);
      if (this.getSelected()?.cveId !== cveId) return;
      this.selectedDetails = details;
    } finally {
      if (this.getSelected()?.cveId === cveId) {
        this.loadingDetails = false;
        this.invalidate();
      }
    }
  }

  private scrollOffsetFor(visibleRows: number): number {
    if (this.selectedIndex < this.scrollOffset) this.scrollOffset = this.selectedIndex;
    if (this.selectedIndex >= this.scrollOffset + visibleRows) this.scrollOffset = this.selectedIndex - visibleRows + 1;
    return this.scrollOffset;
  }

  private renderResultPair(result: KevSearchResult, isSelected: boolean, width: number): [string, string] {
    const prefix = isSelected ? this.theme.fg("accent", "▌") : this.theme.fg("muted", "│");
    const cve = isSelected ? this.theme.fg("accent", this.theme.bold(result.cveId)) : this.theme.fg("success", result.cveId);
    const name = isSelected ? this.theme.fg("text", this.theme.bold(result.name)) : this.theme.fg("text", result.name);
    const badgeText = badges(this.theme, result).join(` ${this.theme.fg("muted", "•")} `);

    const line1Raw = `${prefix} ${cve} ${name}${badgeText ? ` ${this.theme.fg("muted", "•")} ${badgeText}` : ""}`;
    const metaParts = [
      `${result.vendor} • ${result.product}`,
      `EPSS ${Math.round(result.epssScore * 100)}%`,
      result.isOverdue ? `Due ${result.dueDate ?? "—"}` : undefined,
    ].filter((part): part is string => Boolean(part));
    const line2Raw = `  ${this.theme.fg(isSelected ? "text" : "muted", metaParts.join(" • "))}`;

    if (isSelected) {
      return [selectedRow(this.theme, line1Raw, width), selectedRow(this.theme, line2Raw, width)];
    }
    return [truncateToWidth(line1Raw, width), truncateToWidth(line2Raw, width)];
  }

  private renderResultLines(visible: KevSearchResult[], start: number, width: number, visibleRows: number): string[] {
    const lines: string[] = [];

    for (let row = 0; row < visibleRows; row++) {
      const result = visible[row];
      if (!result) {
        lines.push(row === 0 && this.filtered.length === 0 ? this.theme.fg("muted", " No matches for current filter") : "");
        lines.push("");
        continue;
      }

      const absoluteIndex = start + row;
      const pair = this.renderResultPair(result, absoluteIndex === this.selectedIndex, width);
      lines.push(pair[0], pair[1]);
    }

    return lines;
  }

  private renderFullDetailPage(selected: KevSearchResult | undefined, width: number, height: number): string[] {
    if (!selected) {
      return fitPaneLines(
        [
          this.theme.fg("muted", " Select a KEV to view full detail."),
          this.theme.fg("muted", " Use ↑↓ in the browser, then press Tab to open a dedicated detail view."),
        ],
        width,
        height,
      );
    }

    const loadedDetails = this.selectedDetails?.found && this.selectedDetails.cveId === selected.cveId ? this.selectedDetails : undefined;
    return this.renderFullDetailLines(selected, loadedDetails, width, height);
  }

  private renderPreviewLines(selected: KevSearchResult, loadedDetails: CveDetails | undefined, width: number, height: number): string[] {
    const lines: string[] = [];
    const headerBadges = badges(this.theme, loadedDetails ?? selected);
    const summary = loadedDetails?.description ?? selected.shortDescription;
    const action = loadedDetails?.requiredAction;
    const riskFacts = [
      `EPSS ${Math.round(selected.epssScore * 100)}%`,
      loadedDetails?.cvssPrimary ? `CVSS ${loadedDetails.cvssPrimary.score.toFixed(1)} ${loadedDetails.cvssPrimary.severity}` : undefined,
      selected.isOverdue ? `Due ${selected.dueDate ?? "—"}` : undefined,
    ].filter((part): part is string => Boolean(part));

    lines.push(`${this.theme.fg("accent", selected.cveId)}${headerBadges.length ? ` ${this.theme.fg("muted", "•")} ${headerBadges.join(` ${this.theme.fg("muted", "•")} `)}` : ""}`);
    lines.push(this.theme.fg("text", selected.name));
    lines.push(`${this.theme.fg("text", selected.vendor)} • ${this.theme.fg("muted", selected.product)}`);
    if (riskFacts.length > 0) lines.push(this.theme.fg("muted", riskFacts.join(" • ")));

    lines.push(this.theme.fg("accent", " Why it matters"));
    lines.push(...wrapTextWithAnsi(this.theme.fg("text", summary), Math.max(14, width)).slice(0, 3));

    if (action) {
      lines.push(this.theme.fg("accent", " Next step"));
      lines.push(...wrapTextWithAnsi(this.theme.fg("text", action), Math.max(14, width)).slice(0, 2));
    }

    lines.push(this.theme.fg("muted", " Enter pins this CVE. Tab opens the full detail page."));
    lines.push(actionHintLine(this.theme));
    return fitPaneLines(lines, width, height);
  }

  private renderFullDetailLines(selected: KevSearchResult, loadedDetails: CveDetails | undefined, width: number, height: number): string[] {
    const lines: string[] = [];
    const headerBadges = badges(this.theme, loadedDetails ?? selected);

    lines.push(`${this.theme.fg("accent", selected.cveId)}${headerBadges.length ? ` ${this.theme.fg("dim", "•")} ${headerBadges.join(` ${this.theme.fg("dim", "•")} `)}` : ""}`);
    lines.push(`${this.theme.fg("text", selected.vendor)} • ${this.theme.fg("muted", selected.product)}`);
    lines.push(this.theme.fg("text", selected.name));
    lines.push(this.theme.fg("muted", `Added ${selected.dateAdded ?? "—"} • Due ${selected.dueDate ?? "—"}`));
    lines.push(`${this.theme.fg("text", "EPSS")}: ${riskColor(this.theme, selected.epssScore)} ${epssBar(this.theme, selected.epssScore, Math.max(10, Math.min(20, width - 12)))}`);

    if (!loadedDetails) {
      lines.push(this.theme.fg("muted", this.loadingDetails ? " Loading full CVE details…" : " Full CVE details not available yet."));
      lines.push(this.theme.fg("accent", " Summary"));
      lines.push(...wrapTextWithAnsi(this.theme.fg("text", selected.shortDescription), Math.max(14, width)).slice(0, 6));
      lines.push(actionHintLine(this.theme));
      lines.push(linkHintLine(this.theme));
      return fitPaneLines(lines, width, height);
    }

    const references = loadedDetails.references ?? [];
    const patchReferences = references.filter((ref) => isPatchReference(ref));
    const displayedRefs = (patchReferences.length > 0 ? patchReferences : references).slice(0, 2);

    lines.push(
      loadedDetails.cvssPrimary
        ? `${this.theme.fg("text", "CVSS")}: ${this.theme.fg("text", `${loadedDetails.cvssPrimary.score.toFixed(1)} ${loadedDetails.cvssPrimary.severity}`)}${loadedDetails.cvssPrimary.source ? ` ${this.theme.fg("muted", ` • ${loadedDetails.cvssPrimary.source}`)}` : ""}`
        : this.theme.fg("muted", "CVSS: not available"),
    );
    if (loadedDetails.nvdUrl) {
      lines.push(`${this.theme.fg("text", "NVD")}: ${this.theme.fg("text", summarizeUrl(loadedDetails.nvdUrl))}`);
    }
    const metaSummary: string[] = [];
    if (loadedDetails.cwes?.length) metaSummary.push(`CWEs ${loadedDetails.cwes.slice(0, 3).join(", ")}`);
    if (references.length > 0) metaSummary.push(`${references.length} refs${patchReferences.length ? ` • ${patchReferences.length} patch/advisory` : ""}`);
    if (metaSummary.length > 0) lines.push(this.theme.fg("muted", metaSummary.join(" • ")));

    const appendSection = (title: string, content: string | undefined, maxLines: number) => {
      if (!content) return;
      lines.push(this.theme.fg("accent", ` ${title}`));
      lines.push(...wrapTextWithAnsi(this.theme.fg("text", content), Math.max(14, width)).slice(0, maxLines));
    };

    appendSection("Required action", loadedDetails.requiredAction, 2);
    appendSection("Notes", loadedDetails.notes, 1);
    appendSection("Description", loadedDetails.description ?? selected.shortDescription, 1);

    if (displayedRefs.length > 0) {
      lines.push(this.theme.fg("accent", patchReferences.length > 0 ? " Patch refs" : " Top refs"));
      for (const ref of displayedRefs) {
        lines.push(referenceLine(this.theme, ref));
      }
    }

    lines.push(actionHintLine(this.theme));
    lines.push(linkHintLine(this.theme));
    return fitPaneLines(lines, width, height);
  }
}
