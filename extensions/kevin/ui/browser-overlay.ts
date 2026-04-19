import type { Theme } from "@mariozechner/pi-coding-agent";
import { Key, matchesKey, truncateToWidth, visibleWidth, wrapTextWithAnsi } from "@mariozechner/pi-tui";
import type { CveDetails, KevSearchResult, KevStats } from "../core/types.js";

export interface BrowserAction {
  action: "pin" | "patch" | "exploit" | "controls" | "related";
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
  return `${theme.fg(fillColor, "█".repeat(filled))}${theme.fg("dim", "░".repeat(empty))}`;
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
    const leftWidth = Math.max(42, Math.floor(width * 0.5));
    const rightWidth = Math.max(26, width - leftWidth - 1);
    const visibleRows = 8;
    const start = Math.min(this.scrollOffsetFor(visibleRows), Math.max(0, this.filtered.length - visibleRows));
    const visible = this.filtered.slice(start, start + visibleRows);

    lines.push(truncateToWidth(`${this.theme.fg("accent", this.theme.bold(` ${title} `))}${this.theme.fg("dim", "CISA Known Exploited Vulnerabilities")}`, width));

    if (this.options.stats) {
      lines.push(
        truncateToWidth(
          `${this.theme.fg("text", `${this.options.stats.totalCves} KEVs`)} ${this.theme.fg("dim", "| ")}${this.theme.fg("warning", `${this.options.stats.ransomwareCount} ransomware`)} ${this.theme.fg("dim", "| ")}${this.theme.fg("error", `${this.options.stats.overdueCount} overdue`)}`,
          width,
        ),
      );
    }

    const queryText = this.query ? this.theme.fg("text", this.query) : this.theme.fg("dim", "type to filter by CVE, vendor, product, CWE...");
    lines.push(truncateToWidth(`${this.theme.fg("muted", "Search:")} ${queryText}`, width));
    lines.push(
      truncateToWidth(
        `${this.theme.fg("dim", `Sort ${sortLabel(this.sortMode)}`)}${this.ransomwareOnly ? this.theme.fg("warning", " • ransomware") : ""}${this.overdueOnly ? this.theme.fg("error", " • overdue") : ""}${this.theme.fg("dim", ` • ${this.detailMode}`)}`,
        width,
      ),
    );
    lines.push(truncateToWidth(this.theme.fg("borderMuted", "─".repeat(Math.max(12, width))), width));
    lines.push(joinColumns(this.theme.fg("accent", this.theme.bold(" Results")), this.theme.fg("accent", this.theme.bold(this.detailMode === "detail" ? " Detail" : " Preview")), leftWidth, rightWidth));

    for (let row = 0; row < visibleRows; row++) {
      const result = visible[row];
      const detailPair = this.renderDetailPair(selected, row, rightWidth);

      if (!result) {
        const emptyLeft = row === 0 && this.filtered.length === 0 ? this.theme.fg("dim", " No matches for current filter") : "";
        lines.push(joinColumns(emptyLeft, detailPair[0] ?? "", leftWidth, rightWidth));
        lines.push(joinColumns("", detailPair[1] ?? "", leftWidth, rightWidth));
        continue;
      }

      const absoluteIndex = start + row;
      const pair = this.renderResultPair(result, absoluteIndex === this.selectedIndex, leftWidth);
      lines.push(joinColumns(pair[0], detailPair[0] ?? "", leftWidth, rightWidth));
      lines.push(joinColumns(pair[1], detailPair[1] ?? "", leftWidth, rightWidth));
    }

    lines.push(truncateToWidth(this.theme.fg("borderMuted", "─".repeat(Math.max(12, width))), width));
    lines.push(
      truncateToWidth(
        `${this.theme.fg("dim", `${this.filtered.length} result(s)`)}${selected ? this.theme.fg("dim", ` • selected ${selected.cveId}`) : ""}${this.filtered.length > visibleRows ? this.theme.fg("dim", ` • showing ${start + 1}-${Math.min(start + visibleRows, this.filtered.length)}`) : ""}`,
        width,
      ),
    );
    lines.push(truncateToWidth(this.theme.fg("dim", "type to search • ↑↓ move • PgUp/PgDn jump • Ctrl+S sort • Ctrl+R ransomware • Ctrl+O overdue"), width));
    lines.push(truncateToWidth(this.theme.fg("dim", "Tab detail/preview • Enter pin • Ctrl+P patch • Ctrl+E exploit • Ctrl+G controls • Ctrl+L related • Esc close"), width));
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
    const prefix = isSelected ? this.theme.fg("accent", "▌") : this.theme.fg("dim", "│");
    const cve = isSelected ? this.theme.fg("accent", result.cveId) : this.theme.fg("success", result.cveId);
    const name = isSelected ? this.theme.fg("text", result.name) : this.theme.fg("muted", result.name);
    const badgeText = badges(this.theme, result).join(` ${this.theme.fg("dim", "•")} `);

    const line1Raw = `${prefix} ${cve} ${name}${badgeText ? ` ${this.theme.fg("dim", "•")} ${badgeText}` : ""}`;
    const meta = `${result.vendor} | ${result.product} | Added: ${result.dateAdded ?? "—"} | EPSS:`;
    const line2Raw = `  ${this.theme.fg("dim", meta)} ${riskColor(this.theme, result.epssScore)} ${epssBar(this.theme, result.epssScore, Math.max(8, Math.min(14, width - 36)))}`;

    if (isSelected) {
      return [selectedRow(this.theme, line1Raw, width), selectedRow(this.theme, line2Raw, width)];
    }
    return [truncateToWidth(line1Raw, width), truncateToWidth(line2Raw, width)];
  }

  private renderDetailPair(selected: KevSearchResult | undefined, rowIndex: number, width: number): [string, string] {
    if (!selected) {
      if (rowIndex === 0) return [this.theme.fg("dim", " Select a KEV to preview and pin context."), ""];
      return ["", ""];
    }

    const detailLines: string[] = [];

    if (this.detailMode === "detail" && this.loadingDetails) {
      detailLines.push(this.theme.fg("dim", " Loading full CVE details…"));
    } else if (this.detailMode === "detail" && this.selectedDetails?.found) {
      const details = this.selectedDetails;
      detailLines.push(`${this.theme.fg("accent", details.cveId)}${badges(this.theme, details).length ? ` ${this.theme.fg("dim", "•")} ${badges(this.theme, details).join(` ${this.theme.fg("dim", "•")} `)}` : ""}`);
      detailLines.push(`${this.theme.fg("text", details.vendor ?? "")} • ${this.theme.fg("muted", details.product ?? "")}`);
      detailLines.push(`${this.theme.fg("dim", `Added ${details.dateAdded ?? "—"} • Due ${details.dueDate ?? "—"}`)}`);
      detailLines.push(`${this.theme.fg("muted", "EPSS")}: ${riskColor(this.theme, details.epssScore ?? 0)} ${epssBar(this.theme, details.epssScore ?? 0, Math.max(10, Math.min(20, width - 12)))}`);
      if (details.cvssPrimary) detailLines.push(`${this.theme.fg("muted", "CVSS")}: ${this.theme.fg("text", `${details.cvssPrimary.score.toFixed(1)} ${details.cvssPrimary.severity}`)}`);
      if (details.requiredAction) {
        detailLines.push("");
        detailLines.push(this.theme.fg("accent", " Required action"));
        detailLines.push(...wrapTextWithAnsi(this.theme.fg("muted", details.requiredAction), Math.max(14, width)).slice(0, 4));
      }
      if (details.description) {
        detailLines.push("");
        detailLines.push(this.theme.fg("accent", " Description"));
        detailLines.push(...wrapTextWithAnsi(this.theme.fg("muted", details.description), Math.max(14, width)).slice(0, 4));
      }
    } else {
      detailLines.push(`${this.theme.fg("accent", selected.cveId)}${badges(this.theme, selected).length ? ` ${this.theme.fg("dim", "•")} ${badges(this.theme, selected).join(` ${this.theme.fg("dim", "•")} `)}` : ""}`);
      detailLines.push(`${this.theme.fg("text", selected.vendor)} • ${this.theme.fg("muted", selected.product)}`);
      detailLines.push(`${this.theme.fg("dim", `Added ${selected.dateAdded ?? "—"} • Due ${selected.dueDate ?? "—"}`)}`);
      detailLines.push(`${this.theme.fg("muted", "EPSS")}: ${riskColor(this.theme, selected.epssScore)} ${epssBar(this.theme, selected.epssScore, Math.max(10, Math.min(20, width - 12)))}`);
      detailLines.push("");
      detailLines.push(...wrapTextWithAnsi(this.theme.fg("muted", selected.shortDescription), Math.max(14, width)).slice(0, 9));
    }

    const start = rowIndex * 2;
    return [truncateToWidth(detailLines[start] ?? "", width), truncateToWidth(detailLines[start + 1] ?? "", width)];
  }
}
