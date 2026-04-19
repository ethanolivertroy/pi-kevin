import { KevStore } from "./kev-store.js";
import type {
  AnalyzeCweResult,
  BatchAnalyzeResult,
  KevRecord,
  KevSearchResult,
  RelatedCveItem,
  RelatedCvesResult,
  TrendAnalysisResult,
  VendorRiskProfile,
} from "./types.js";

const RiskScoreBaseCveWeight = 2.0;
const RiskScoreBaseCap = 30.0;
const RiskScoreRansomwareWeight = 5.0;
const RiskScoreRansomwareCap = 25.0;
const RiskScoreOverdueWeight = 3.0;
const RiskScoreOverdueCap = 25.0;
const RiskScoreEpssWeight = 20.0;
const RiskScoreMaxTotal = 100.0;

const RiskPriorityEpssWeight = 40.0;
const RiskPriorityRansomwareBonus = 30.0;
const RiskPriorityOverdueBonus = 20.0;

const cweInfo: Record<string, { name: string; mitigations: string[] }> = {
  "CWE-78": { name: "OS Command Injection", mitigations: ["Input validation", "Use parameterized commands", "Avoid shell execution", "Principle of least privilege"] },
  "CWE-79": { name: "Cross-site Scripting (XSS)", mitigations: ["Output encoding", "Content Security Policy", "Input validation", "Use frameworks with auto-escaping"] },
  "CWE-89": { name: "SQL Injection", mitigations: ["Parameterized queries", "Stored procedures", "Input validation", "Least privilege database accounts"] },
  "CWE-94": { name: "Code Injection", mitigations: ["Input validation", "Avoid dynamic code execution", "Sandboxing", "Code review"] },
  "CWE-119": { name: "Buffer Overflow", mitigations: ["Bounds checking", "Use safe functions", "ASLR/DEP", "Memory-safe languages"] },
  "CWE-200": { name: "Information Exposure", mitigations: ["Access controls", "Data classification", "Encryption", "Audit logging"] },
  "CWE-269": { name: "Improper Privilege Management", mitigations: ["Principle of least privilege", "Role-based access control", "Regular access reviews"] },
  "CWE-287": { name: "Improper Authentication", mitigations: ["Multi-factor authentication", "Strong password policies", "Account lockout", "Session management"] },
  "CWE-352": { name: "Cross-Site Request Forgery (CSRF)", mitigations: ["CSRF tokens", "SameSite cookies", "Verify origin header", "Re-authentication for sensitive actions"] },
  "CWE-434": { name: "Unrestricted File Upload", mitigations: ["File type validation", "Content inspection", "Isolated storage", "Rename uploaded files"] },
  "CWE-502": { name: "Deserialization of Untrusted Data", mitigations: ["Avoid deserializing untrusted data", "Use safe serialization formats", "Input validation", "Integrity checks"] },
  "CWE-611": { name: "XXE (XML External Entity)", mitigations: ["Disable external entities", "Use less complex data formats", "Input validation", "Update XML parsers"] },
  "CWE-787": { name: "Out-of-bounds Write", mitigations: ["Bounds checking", "Safe memory functions", "ASLR/DEP", "Code review"] },
  "CWE-918": { name: "Server-Side Request Forgery (SSRF)", mitigations: ["URL validation", "Allowlist destinations", "Network segmentation", "Disable unnecessary protocols"] },
};

function normalizeCwe(input: string | undefined): string {
  const cleaned = (input ?? "").trim().toUpperCase().replace(/^CWE-/, "");
  return cleaned ? `CWE-${cleaned}` : "";
}

function isOverdue(date: string | undefined): boolean {
  if (!date) return false;
  const timestamp = Date.parse(date);
  return Number.isFinite(timestamp) && timestamp < Date.now();
}

function toSearchResult(record: KevRecord): KevSearchResult {
  return {
    cveId: record.cveId,
    vendor: record.vendorProject,
    product: record.product,
    name: record.vulnerabilityName,
    dateAdded: record.dateAdded,
    dueDate: record.dueDate,
    ransomwareUse: record.ransomwareUse,
    isOverdue: isOverdue(record.dueDate),
    epssScore: record.epss?.score ?? 0,
    epssPercentile: record.epss?.percentile ?? 0,
    shortDescription: record.shortDescription,
  };
}

function containsIgnoreCase(haystack: string, needle: string): boolean {
  return haystack.toLowerCase().includes(needle.toLowerCase());
}

function calculateVendorRiskScore(totalCves: number, ransomwareCves: number, overdueCves: number, avgEpss: number): number {
  const baseScore = Math.min(totalCves * RiskScoreBaseCveWeight, RiskScoreBaseCap);
  const ransomwareScore = Math.min(ransomwareCves * RiskScoreRansomwareWeight, RiskScoreRansomwareCap);
  const overdueScore = Math.min(overdueCves * RiskScoreOverdueWeight, RiskScoreOverdueCap);
  const epssScore = avgEpss * RiskScoreEpssWeight;
  return Math.min(baseScore + ransomwareScore + overdueScore + epssScore, RiskScoreMaxTotal);
}

function riskLevel(score: number): string {
  if (score >= 75) return "CRITICAL";
  if (score >= 50) return "HIGH";
  if (score >= 25) return "MEDIUM";
  return "LOW";
}

function riskPriority(epss: number, overdue: boolean, ransomware: boolean): string {
  let score = epss * RiskPriorityEpssWeight;
  if (ransomware) score += RiskPriorityRansomwareBonus;
  if (overdue) score += RiskPriorityOverdueBonus;
  if (score >= 70) return "CRITICAL";
  if (score >= 50) return "HIGH";
  if (score >= 25) return "MEDIUM";
  return "LOW";
}

export class KevAnalytics {
  constructor(private readonly store: KevStore) {}

  async findRelatedCves(params: { cveId?: string; cwe?: string; vendor?: string; product?: string; limit?: number }): Promise<RelatedCvesResult> {
    const snapshot = await this.store.getCatalog();
    const limit = params.limit && params.limit > 0 ? params.limit : 10;

    let sourceVendor = "";
    let sourceProduct = "";
    let sourceCves: string[] = [];
    let sourceCveId = "";
    let query = "";

    if (params.cveId) {
      sourceCveId = params.cveId.trim().toUpperCase();
      const source = snapshot.records.find((record) => record.cveId === sourceCveId);
      if (!source) {
        return { query: `CVE ${sourceCveId} not found`, count: 0, relatedCves: [] };
      }
      sourceVendor = source.vendorProject;
      sourceProduct = source.product;
      sourceCves = source.cwes;
      query = `CVEs related to ${sourceCveId} (${sourceVendor} ${sourceProduct})`;
    }

    if (!query) {
      const pieces = [params.cwe ? `CWE: ${normalizeCwe(params.cwe)}` : undefined, params.vendor ? `Vendor: ${params.vendor}` : undefined, params.product ? `Product: ${params.product}` : undefined].filter(Boolean);
      query = `CVEs matching: ${pieces.join(", ")}`;
      sourceVendor = params.vendor ?? "";
      sourceProduct = params.product ?? "";
    }

    const targetCwe = normalizeCwe(params.cwe) || normalizeCwe(sourceCves[0]);
    const related: RelatedCveItem[] = [];

    for (const record of snapshot.records) {
      if (sourceCveId && record.cveId === sourceCveId) continue;
      const reasons: string[] = [];

      if (targetCwe && record.cwes.some((cwe) => normalizeCwe(cwe) === targetCwe)) reasons.push(`Same CWE (${targetCwe})`);
      if (sourceVendor && record.vendorProject.toLowerCase() === sourceVendor.toLowerCase()) reasons.push("Same vendor");
      if (sourceProduct && record.product.toLowerCase() === sourceProduct.toLowerCase()) reasons.push("Same product");
      if (params.vendor && containsIgnoreCase(record.vendorProject, params.vendor) && !reasons.includes("Same vendor")) reasons.push("Matching vendor");
      if (params.product && containsIgnoreCase(record.product, params.product) && !reasons.includes("Same product")) reasons.push("Matching product");

      if (reasons.length === 0) continue;
      related.push({
        cveId: record.cveId,
        vendor: record.vendorProject,
        product: record.product,
        name: record.vulnerabilityName,
        similarity: reasons.join(", "),
        cwes: record.cwes,
        epssScore: record.epss?.score ?? 0,
        isOverdue: isOverdue(record.dueDate),
        ransomwareUse: record.ransomwareUse,
      });
    }

    related.sort((a, b) => b.epssScore - a.epssScore);
    return {
      query,
      count: Math.min(limit, related.length),
      relatedCves: related.slice(0, limit),
      commonCwes: sourceCves,
      commonVendor: sourceVendor || undefined,
    };
  }

  async getVendorRiskProfile(vendor: string): Promise<VendorRiskProfile> {
    const snapshot = await this.store.getCatalog();
    const target = vendor.trim().toLowerCase();
    const matches = snapshot.records.filter((record) => containsIgnoreCase(record.vendorProject, target));
    if (matches.length === 0) return { vendor, found: false };

    let totalEpss = 0;
    let maxEpss = 0;
    let ransomwareCves = 0;
    let overdueCves = 0;
    let oldestUnpatched: string | undefined;
    const productStats = new Map<string, { count: number; ransomware: number; epss: number }>();
    const cweCounts = new Map<string, number>();

    for (const record of matches) {
      const epss = record.epss?.score ?? 0;
      totalEpss += epss;
      maxEpss = Math.max(maxEpss, epss);
      if (record.ransomwareUse) ransomwareCves += 1;
      if (isOverdue(record.dueDate)) {
        overdueCves += 1;
        if (!oldestUnpatched || (record.dateAdded ?? "") < oldestUnpatched) oldestUnpatched = record.dateAdded;
      }

      const product = productStats.get(record.product) ?? { count: 0, ransomware: 0, epss: 0 };
      product.count += 1;
      product.epss += epss;
      if (record.ransomwareUse) product.ransomware += 1;
      productStats.set(record.product, product);

      for (const cwe of record.cwes) cweCounts.set(cwe, (cweCounts.get(cwe) ?? 0) + 1);
    }

    const averageEpss = totalEpss / matches.length;
    const riskScore = calculateVendorRiskScore(matches.length, ransomwareCves, overdueCves, averageEpss);

    return {
      vendor,
      found: true,
      totalCves: matches.length,
      ransomwareCves,
      overdueCves,
      averageEpss,
      maxEpss,
      riskScore,
      riskLevel: riskLevel(riskScore),
      topProducts: [...productStats.entries()]
        .map(([product, data]) => ({ product, cveCount: data.count, ransomwareCount: data.ransomware, avgEpss: data.count ? data.epss / data.count : 0 }))
        .sort((a, b) => b.cveCount - a.cveCount)
        .slice(0, 5),
      topCwes: [...cweCounts.entries()].sort((a, b) => b[1] - a[1]).slice(0, 5).map(([cwe]) => cwe),
      recentCves: matches.slice().sort((a, b) => (b.dateAdded ?? "").localeCompare(a.dateAdded ?? "")).slice(0, 5).map(toSearchResult),
      oldestUnpatched,
    };
  }

  async batchAnalyze(cveIds: string[]): Promise<BatchAnalyzeResult> {
    const snapshot = await this.store.getCatalog();
    const map = new Map(snapshot.records.map((record) => [record.cveId, record]));
    const notFound: string[] = [];
    const analyses: BatchAnalyzeResult["cves"] = [];
    const vendorCounts = new Map<string, number>();
    const cweCounts = new Map<string, number>();
    let totalEpss = 0;
    let maxEpss = 0;
    let overdueCount = 0;
    let ransomwareCount = 0;
    let criticalPriority = 0;
    let highPriority = 0;
    let mediumPriority = 0;
    let lowPriority = 0;

    for (const raw of cveIds) {
      const cveId = raw.trim().toUpperCase();
      const record = map.get(cveId);
      if (!record) {
        notFound.push(cveId);
        analyses.push({ cveId, found: false });
        continue;
      }

      const overdue = isOverdue(record.dueDate);
      const epss = record.epss?.score ?? 0;
      const priority = riskPriority(epss, overdue, record.ransomwareUse);
      if (priority === "CRITICAL") criticalPriority += 1;
      else if (priority === "HIGH") highPriority += 1;
      else if (priority === "MEDIUM") mediumPriority += 1;
      else lowPriority += 1;

      if (overdue) overdueCount += 1;
      if (record.ransomwareUse) ransomwareCount += 1;
      totalEpss += epss;
      maxEpss = Math.max(maxEpss, epss);
      vendorCounts.set(record.vendorProject, (vendorCounts.get(record.vendorProject) ?? 0) + 1);
      for (const cwe of record.cwes) cweCounts.set(cwe, (cweCounts.get(cwe) ?? 0) + 1);

      analyses.push({
        cveId,
        found: true,
        vendor: record.vendorProject,
        product: record.product,
        name: record.vulnerabilityName,
        epssScore: epss,
        epssPercentile: record.epss?.percentile ?? 0,
        isOverdue: overdue,
        daysOverdue: overdue && record.dueDate ? Math.floor((Date.now() - Date.parse(record.dueDate)) / (1000 * 60 * 60 * 24)) : 0,
        ransomwareUse: record.ransomwareUse,
        cwes: record.cwes,
        riskPriority: priority,
      });
    }

    analyses.sort((a, b) => {
      const order = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3 } as const;
      const aOrder = a.riskPriority ? order[a.riskPriority as keyof typeof order] ?? 4 : 5;
      const bOrder = b.riskPriority ? order[b.riskPriority as keyof typeof order] ?? 4 : 5;
      return aOrder - bOrder;
    });

    const found = analyses.filter((analysis) => analysis.found).length;
    return {
      count: cveIds.length,
      found,
      notFound,
      cves: analyses,
      summary: {
        totalAnalyzed: found,
        overdueCount,
        ransomwareCount,
        avgEpss: found ? totalEpss / found : 0,
        maxEpss,
        criticalPriority,
        highPriority,
        mediumPriority,
        lowPriority,
        commonVendors: [...vendorCounts.entries()].sort((a, b) => b[1] - a[1]).slice(0, 3).map(([vendor]) => vendor),
        commonCwes: [...cweCounts.entries()].sort((a, b) => b[1] - a[1]).slice(0, 3).map(([cwe]) => cwe),
      },
    };
  }

  async analyzeCwe(cweRaw: string, limitRaw?: number): Promise<AnalyzeCweResult> {
    const snapshot = await this.store.getCatalog();
    const cwe = normalizeCwe(cweRaw);
    const limit = limitRaw && limitRaw > 0 ? limitRaw : 10;
    if (!cwe) return { cwe: cweRaw, found: false };

    const matches = snapshot.records.filter((record) => record.cwes.some((item) => normalizeCwe(item) === cwe));
    if (matches.length === 0) return { cwe, found: false };

    const vendorCounts = new Map<string, number>();
    const products = new Set<string>();
    let totalEpss = 0;
    let ransomwareCves = 0;
    let overdueCves = 0;

    for (const record of matches) {
      vendorCounts.set(record.vendorProject, (vendorCounts.get(record.vendorProject) ?? 0) + 1);
      products.add(record.product);
      totalEpss += record.epss?.score ?? 0;
      if (record.ransomwareUse) ransomwareCves += 1;
      if (isOverdue(record.dueDate)) overdueCves += 1;
    }

    return {
      cwe,
      cweName: cweInfo[cwe]?.name,
      found: true,
      totalCves: matches.length,
      ransomwareCves,
      overdueCves,
      averageEpss: totalEpss / matches.length,
      affectedVendors: [...vendorCounts.entries()].sort((a, b) => b[1] - a[1]).slice(0, 10).map(([vendor, count]) => ({ vendor, count })),
      affectedProducts: [...products].sort().slice(0, 10),
      cves: matches.slice(0, limit).map(toSearchResult),
      mitigations: cweInfo[cwe]?.mitigations,
    };
  }

  async analyzeTrends(params: { days?: number; vendor?: string; cwe?: string }): Promise<TrendAnalysisResult> {
    const snapshot = await this.store.getCatalog();
    const days = params.days && params.days > 0 ? params.days : 90;
    const cutoff = Date.now() - days * 24 * 60 * 60 * 1000;
    const normalizedCwe = normalizeCwe(params.cwe);
    const vendorFilter = params.vendor?.trim().toLowerCase();

    const filtered = snapshot.records.filter((record) => {
      const added = record.dateAdded ? Date.parse(record.dateAdded) : 0;
      if (!Number.isFinite(added) || added < cutoff) return false;
      if (vendorFilter && !containsIgnoreCase(record.vendorProject, vendorFilter)) return false;
      if (normalizedCwe && !record.cwes.some((cwe) => normalizeCwe(cwe) === normalizedCwe)) return false;
      return true;
    });

    const weekCounts = new Map<string, number>();
    const vendorCounts = new Map<string, number>();
    const cweCounts = new Map<string, number>();
    let ransomwareTotal = 0;

    for (const record of filtered) {
      const date = record.dateAdded ? new Date(record.dateAdded) : new Date();
      const year = date.getUTCFullYear();
      const firstDay = new Date(Date.UTC(year, 0, 1));
      const dayOfYear = Math.floor((date.getTime() - firstDay.getTime()) / (24 * 60 * 60 * 1000));
      const week = Math.ceil((dayOfYear + firstDay.getUTCDay() + 1) / 7);
      const key = `${year}-W${String(week).padStart(2, "0")}`;
      weekCounts.set(key, (weekCounts.get(key) ?? 0) + 1);
      vendorCounts.set(record.vendorProject, (vendorCounts.get(record.vendorProject) ?? 0) + 1);
      for (const cwe of record.cwes) cweCounts.set(cwe, (cweCounts.get(cwe) ?? 0) + 1);
      if (record.ransomwareUse) ransomwareTotal += 1;
    }

    const weekly = [...weekCounts.entries()].sort((a, b) => a[0].localeCompare(b[0])).map(([week, count]) => ({ week, count }));
    let riskTrend = "STABLE";
    if (weekly.length >= 4) {
      const mid = Math.floor(weekly.length / 2);
      const earlier = weekly.slice(0, mid).reduce((sum, item) => sum + item.count, 0);
      const recent = weekly.slice(mid).reduce((sum, item) => sum + item.count, 0);
      if (recent > earlier * 2) riskTrend = "INCREASING - Recent activity significantly higher";
      else if (recent > earlier) riskTrend = "SLIGHTLY INCREASING";
      else if (earlier > recent * 2) riskTrend = "DECREASING - Recent activity lower";
    }

    return {
      period: `Last ${days} days`,
      totalCves: filtered.length,
      newCvesPerWeek: weekly,
      topVendors: [...vendorCounts.entries()].sort((a, b) => b[1] - a[1]).slice(0, 10).map(([vendor, count]) => ({ vendor, count })),
      topCwes: [...cweCounts.entries()].sort((a, b) => b[1] - a[1]).slice(0, 10).map(([cwe, count]) => ({ cwe, name: cweInfo[cwe]?.name, count })),
      ransomwareTrend: { total: ransomwareTotal, percentage: filtered.length ? (ransomwareTotal / filtered.length) * 100 : 0 },
      riskTrend,
    };
  }
}
