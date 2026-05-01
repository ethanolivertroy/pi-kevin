import { isFresh, readJsonCache, writeJsonCache } from "./cache.js";
import type {
  AdvisoryInfo,
  CveDetails,
  CvssMetric,
  EpssScore,
  ExploitAvailabilityResult,
  KevCatalogSnapshot,
  KevRecord,
  KevSearchResult,
  KevStats,
  PatchReference,
  PatchStatusResult,
} from "./types.js";

const KEV_URL = "https://raw.githubusercontent.com/cisagov/kev-data/main/known_exploited_vulnerabilities.json";
const EPSS_URL = "https://api.first.org/data/v1/epss";
const NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0";

const KEV_TTL_MS = 12 * 60 * 60 * 1000;
const NVD_TTL_MS = 24 * 60 * 60 * 1000;
const EPSS_BATCH_SIZE = 100;

interface KevApiResponse {
  vulnerabilities: Array<{
    cveID: string;
    vendorProject: string;
    product: string;
    vulnerabilityName: string;
    shortDescription: string;
    requiredAction: string;
    notes: string;
    cwes?: string[];
    knownRansomwareCampaignUse?: string;
    dateAdded?: string;
    dueDate?: string;
  }>;
}

interface EpssApiResponse {
  data?: Array<{
    cve: string;
    epss: string;
    percentile: string;
  }>;
}

interface NvdApiResponse {
  vulnerabilities?: Array<{
    cve?: {
      id?: string;
      references?: Array<{
        url?: string;
        source?: string;
        tags?: string[];
      }>;
      metrics?: {
        cvssMetricV31?: NvdMetric[];
        cvssMetricV30?: NvdMetric[];
        cvssMetricV2?: NvdMetricV2[];
      };
    };
  }>;
}

interface NvdMetric {
  source?: string;
  type?: string;
  cvssData?: {
    version?: string;
    baseScore?: number;
    baseSeverity?: string;
    vectorString?: string;
  };
}

interface NvdMetricV2 {
  source?: string;
  type?: string;
  baseSeverity?: string;
  cvssData?: {
    version?: string;
    baseScore?: number;
    vectorString?: string;
  };
}

function normalizeText(value: string | undefined): string {
  return (value ?? "").trim();
}

function toIsoDate(input: string | undefined): string | undefined {
  if (!input) return undefined;
  const trimmed = input.trim();
  return trimmed.length > 0 ? trimmed : undefined;
}

function isOverdue(date: string | undefined): boolean {
  if (!date) return false;
  const ts = Date.parse(date);
  return Number.isFinite(ts) && ts < Date.now();
}

function scoreQuery(record: KevRecord, query: string): number {
  const q = query.trim().toLowerCase();
  if (!q) return 1;

  const cve = record.cveId.toLowerCase();
  const vendor = record.vendorProject.toLowerCase();
  const product = record.product.toLowerCase();
  const name = record.vulnerabilityName.toLowerCase();
  const desc = record.shortDescription.toLowerCase();

  if (cve === q) return 200;
  if (cve.startsWith(q)) return 150;
  if (vendor === q) return 120;
  if (product === q) return 110;
  if (name.includes(q)) return 100;
  if (vendor.includes(q)) return 90;
  if (product.includes(q)) return 80;
  if (desc.includes(q)) return 50;
  if (record.cwes.some((cwe) => cwe.toLowerCase().includes(q))) return 70;
  return 0;
}

function uniqueByUrl(references: PatchReference[]): PatchReference[] {
  const seen = new Set<string>();
  const output: PatchReference[] = [];
  for (const ref of references) {
    if (!ref.url || seen.has(ref.url)) continue;
    seen.add(ref.url);
    output.push(ref);
  }
  return output;
}

function mapMetric(metric: NvdMetric | NvdMetricV2): CvssMetric | undefined {
  const cvssData = metric.cvssData;
  if (!cvssData || typeof cvssData.baseScore !== "number") return undefined;
  const severity = "baseSeverity" in metric ? (metric.baseSeverity ?? "UNKNOWN") : ((cvssData as { baseSeverity?: string }).baseSeverity ?? "UNKNOWN");
  return {
    version: cvssData.version ?? "unknown",
    score: cvssData.baseScore,
    severity,
    vector: cvssData.vectorString,
    source: metric.source,
    type: metric.type,
  };
}

function classifyReferences(references: PatchReference[]): { advisories: AdvisoryInfo[]; patchReferences: PatchReference[] } {
  const advisories: AdvisoryInfo[] = [];
  const patchReferences: PatchReference[] = [];

  for (const ref of references) {
    const tags = ref.tags ?? [];
    const tagText = tags.join(" ").toLowerCase();
    const lowerUrl = ref.url.toLowerCase();
    const isPatch =
      tagText.includes("patch") ||
      tagText.includes("vendor advisory") ||
      lowerUrl.includes("advisory") ||
      lowerUrl.includes("security") ||
      lowerUrl.includes("release-note") ||
      lowerUrl.includes("support") ||
      lowerUrl.includes("kb/");

    if (isPatch) {
      patchReferences.push(ref);
      advisories.push({
        vendor: ref.source ?? extractVendorFromUrl(ref.url),
        url: ref.url,
      });
    }
  }

  return {
    advisories: uniqueAdvisories(advisories),
    patchReferences: uniqueByUrl(patchReferences),
  };
}

function uniqueAdvisories(advisories: AdvisoryInfo[]): AdvisoryInfo[] {
  const seen = new Set<string>();
  const result: AdvisoryInfo[] = [];
  for (const advisory of advisories) {
    if (seen.has(advisory.url)) continue;
    seen.add(advisory.url);
    result.push(advisory);
  }
  return result;
}

function extractVendorFromUrl(url: string): string {
  try {
    const host = new URL(url).hostname.replace(/^www\./, "");
    return host.split(".")[0] ?? host;
  } catch {
    return "vendor";
  }
}

function classifyExploitSignals(references: PatchReference[]): string[] {
  const signals = new Set<string>();
  for (const ref of references) {
    const tags = (ref.tags ?? []).join(" ").toLowerCase();
    const url = ref.url.toLowerCase();

    if (tags.includes("exploit") || url.includes("exploit-db") || url.includes("metasploit")) {
      signals.add("exploit-reference");
    }
    if (url.includes("github.com")) {
      signals.add("github-reference");
    }
    if (url.includes("packetstorm")) {
      signals.add("packetstorm-reference");
    }
    if (url.includes("nuclei") || url.includes("projectdiscovery")) {
      signals.add("nuclei-reference");
    }
    if (url.includes("poc") || tags.includes("technical description")) {
      signals.add("poc-signal");
    }
  }
  return [...signals];
}

async function fetchJson<T>(url: string): Promise<T> {
  const response = await fetch(url, {
    headers: {
      "user-agent": "pi-kevin/0.1.0",
      accept: "application/json",
    },
  });

  if (!response.ok) {
    throw new Error(`Request failed (${response.status}) for ${url}`);
  }

  return (await response.json()) as T;
}

export class KevStore {
  private catalogPromise?: Promise<KevCatalogSnapshot>;

  async getCatalog(forceRefresh = false): Promise<KevCatalogSnapshot> {
    if (!forceRefresh && this.catalogPromise) {
      return this.catalogPromise;
    }

    this.catalogPromise = this.loadCatalog(forceRefresh);
    return this.catalogPromise;
  }

  async search(params: {
    query?: string;
    vendor?: string;
    ransomwareOnly?: boolean;
    overdueOnly?: boolean;
    limit?: number;
  }): Promise<KevSearchResult[]> {
    const snapshot = await this.getCatalog();
    const query = normalizeText(params.query);
    const vendor = normalizeText(params.vendor).toLowerCase();
    const limit = params.limit && params.limit > 0 ? params.limit : 10;

    const results = snapshot.records
      .map((record) => ({ record, score: scoreQuery(record, query) }))
      .filter(({ record, score }) => {
        if (vendor && !record.vendorProject.toLowerCase().includes(vendor)) return false;
        if (params.ransomwareOnly && !record.ransomwareUse) return false;
        if (params.overdueOnly && !isOverdue(record.dueDate)) return false;
        if (query && score <= 0) return false;
        return true;
      })
      .sort((a, b) => {
        if (query) return b.score - a.score;
        return (b.record.dateAdded ?? "").localeCompare(a.record.dateAdded ?? "");
      })
      .slice(0, limit)
      .map(({ record }) => this.toSearchResult(record));

    return results;
  }

  async listRansomware(limit = 10): Promise<KevSearchResult[]> {
    return this.search({ ransomwareOnly: true, limit });
  }

  async listOverdue(limit = 10): Promise<KevSearchResult[]> {
    return this.search({ overdueOnly: true, limit });
  }

  async getStats(topN = 10): Promise<KevStats> {
    const snapshot = await this.getCatalog();
    const vendorCounts = new Map<string, number>();
    const cweCounts = new Map<string, number>();

    let ransomwareCount = 0;
    let overdueCount = 0;

    for (const record of snapshot.records) {
      vendorCounts.set(record.vendorProject, (vendorCounts.get(record.vendorProject) ?? 0) + 1);
      if (record.ransomwareUse) ransomwareCount += 1;
      if (isOverdue(record.dueDate)) overdueCount += 1;
      for (const cwe of record.cwes) {
        cweCounts.set(cwe, (cweCounts.get(cwe) ?? 0) + 1);
      }
    }

    return {
      totalCves: snapshot.records.length,
      ransomwareCount,
      overdueCount,
      topVendors: [...vendorCounts.entries()]
        .sort((a, b) => b[1] - a[1])
        .slice(0, topN)
        .map(([vendor, count]) => ({ vendor, count })),
      topCwes: [...cweCounts.entries()]
        .sort((a, b) => b[1] - a[1])
        .slice(0, topN)
        .map(([cwe, count]) => ({ cwe, count })),
    };
  }

  async getCveDetails(cveIdRaw: string): Promise<CveDetails> {
    const cveId = cveIdRaw.trim().toUpperCase();
    const snapshot = await this.getCatalog();
    const record = snapshot.records.find((item) => item.cveId === cveId);

    if (!record) {
      return { found: false, cveId };
    }

    const nvd = await this.getNvdDetails(cveId);

    return {
      found: true,
      cveId: record.cveId,
      vendor: record.vendorProject,
      product: record.product,
      name: record.vulnerabilityName,
      description: record.shortDescription,
      dateAdded: record.dateAdded,
      dueDate: record.dueDate,
      requiredAction: record.requiredAction,
      notes: record.notes,
      cwes: record.cwes,
      ransomwareUse: record.ransomwareUse,
      isOverdue: isOverdue(record.dueDate),
      epssScore: record.epss?.score ?? 0,
      epssPercentile: record.epss?.percentile ?? 0,
      nvdUrl: `https://nvd.nist.gov/vuln/detail/${record.cveId}`,
      cvssPrimary: nvd.cvssPrimary,
      cvssSecondary: nvd.cvssSecondary,
      references: nvd.references,
    };
  }

  async getPatchStatus(cveId: string): Promise<PatchStatusResult> {
    const details = await this.getCveDetails(cveId);
    const references = uniqueByUrl(details.references ?? []);
    const { advisories, patchReferences } = classifyReferences(references);

    return {
      cveId: details.cveId,
      hasPatch: patchReferences.length > 0,
      advisories,
      patchReferences,
      references: references.slice(0, 20),
      nvdUrl: details.nvdUrl ?? `https://nvd.nist.gov/vuln/detail/${details.cveId}`,
    };
  }

  async getExploitAvailability(cveId: string): Promise<ExploitAvailabilityResult> {
    const details = await this.getCveDetails(cveId);
    const references = uniqueByUrl(details.references ?? []);
    const exploitReferences = references.filter((ref) => {
      const combined = `${ref.url} ${(ref.tags ?? []).join(" ")}`.toLowerCase();
      return (
        combined.includes("exploit") ||
        combined.includes("metasploit") ||
        combined.includes("packetstorm") ||
        combined.includes("github.com") ||
        combined.includes("poc") ||
        combined.includes("nuclei")
      );
    });

    return {
      cveId: details.cveId,
      hasPublicExploit: exploitReferences.length > 0,
      exploitSignals: classifyExploitSignals(exploitReferences),
      references: exploitReferences.slice(0, 20),
      githubSearchUrl: `https://github.com/search?q=${encodeURIComponent(details.cveId)}&type=repositories`,
      exploitDbSearchUrl: `https://www.exploit-db.com/search?cve=${encodeURIComponent(details.cveId)}`,
      nucleiSearchUrl: `https://github.com/search?q=${encodeURIComponent(details.cveId + " nuclei")}&type=code`,
    };
  }

  private async loadCatalog(forceRefresh: boolean): Promise<KevCatalogSnapshot> {
    if (!forceRefresh) {
      const cached = await readJsonCache<KevCatalogSnapshot>("kev-catalog.json");
      if (cached && isFresh(cached.fetchedAt, KEV_TTL_MS)) {
        return cached;
      }
    }

    const kevResponse = await fetchJson<KevApiResponse>(KEV_URL);
    const records = kevResponse.vulnerabilities.map<KevRecord>((item) => ({
      cveId: item.cveID,
      vendorProject: item.vendorProject,
      product: item.product,
      vulnerabilityName: item.vulnerabilityName,
      shortDescription: item.shortDescription,
      requiredAction: item.requiredAction,
      notes: item.notes,
      cwes: item.cwes ?? [],
      ransomwareUse: (item.knownRansomwareCampaignUse ?? "").toLowerCase() === "known",
      dateAdded: toIsoDate(item.dateAdded),
      dueDate: toIsoDate(item.dueDate),
    }));

    const epssMap = await this.fetchEpss(records.map((item) => item.cveId));
    for (const record of records) {
      record.epss = epssMap.get(record.cveId) ?? { score: 0, percentile: 0 };
    }

    const snapshot: KevCatalogSnapshot = {
      fetchedAt: Date.now(),
      records,
    };

    await writeJsonCache("kev-catalog.json", snapshot);
    return snapshot;
  }

  private async fetchEpss(cveIds: string[]): Promise<Map<string, EpssScore>> {
    const map = new Map<string, EpssScore>();

    for (let index = 0; index < cveIds.length; index += EPSS_BATCH_SIZE) {
      const batch = cveIds.slice(index, index + EPSS_BATCH_SIZE);
      if (batch.length === 0) continue;

      try {
        const url = `${EPSS_URL}?cve=${encodeURIComponent(batch.join(","))}`;
        const payload = await fetchJson<EpssApiResponse>(url);
        for (const row of payload.data ?? []) {
          map.set(row.cve, {
            score: Number.parseFloat(row.epss) || 0,
            percentile: Number.parseFloat(row.percentile) || 0,
          });
        }
      } catch {
        // Best-effort: keep browsing/search available even if EPSS fails.
      }
    }

    return map;
  }

  private async getNvdDetails(cveId: string): Promise<{
    cvssPrimary?: CvssMetric;
    cvssSecondary: CvssMetric[];
    references: PatchReference[];
  }> {
    const cacheKey = `nvd-${cveId}.json`;
    const cached = await readJsonCache<{
      fetchedAt: number;
      cvssPrimary?: CvssMetric;
      cvssSecondary: CvssMetric[];
      references: PatchReference[];
    }>(cacheKey);

    if (cached && isFresh(cached.fetchedAt, NVD_TTL_MS)) {
      return {
        cvssPrimary: cached.cvssPrimary,
        cvssSecondary: cached.cvssSecondary,
        references: cached.references,
      };
    }

    try {
      const payload = await fetchJson<NvdApiResponse>(`${NVD_URL}?cveId=${encodeURIComponent(cveId)}`);
      const vulnerability = payload.vulnerabilities?.[0]?.cve;
      const metrics = vulnerability?.metrics;

      const cvssPrimary =
        metrics?.cvssMetricV31?.map(mapMetric).find((metric) => metric?.type === "Primary") ??
        metrics?.cvssMetricV30?.map(mapMetric).find((metric) => metric?.type === "Primary") ??
        metrics?.cvssMetricV31?.map(mapMetric).find(Boolean) ??
        metrics?.cvssMetricV30?.map(mapMetric).find(Boolean) ??
        metrics?.cvssMetricV2?.map(mapMetric).find(Boolean);

      const cvssSecondary = [
        ...(metrics?.cvssMetricV31 ?? []),
        ...(metrics?.cvssMetricV30 ?? []),
        ...(metrics?.cvssMetricV2 ?? []),
      ]
        .map(mapMetric)
        .filter((metric): metric is CvssMetric => Boolean(metric))
        .filter((metric) => metric !== cvssPrimary);

      const references = uniqueByUrl(
        (vulnerability?.references ?? [])
          .map<PatchReference | undefined>((ref) => {
            if (!ref.url) return undefined;
            return {
              url: ref.url,
              source: ref.source,
              tags: ref.tags ?? [],
            };
          })
          .filter((ref): ref is PatchReference => Boolean(ref)),
      );

      const result = {
        fetchedAt: Date.now(),
        cvssPrimary,
        cvssSecondary,
        references,
      };

      await writeJsonCache(cacheKey, result);
      return result;
    } catch {
      return {
        cvssPrimary: undefined,
        cvssSecondary: [],
        references: [],
      };
    }
  }

  private toSearchResult(record: KevRecord): KevSearchResult {
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
}
