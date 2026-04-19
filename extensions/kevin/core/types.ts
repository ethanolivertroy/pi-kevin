export interface EpssScore {
  score: number;
  percentile: number;
}

export interface CvssMetric {
  version: string;
  score: number;
  severity: string;
  vector?: string;
  source?: string;
  type?: string;
}

export interface PatchReference {
  url: string;
  source?: string;
  tags?: string[];
}

export interface AdvisoryInfo {
  vendor: string;
  url: string;
}

export interface KevRecord {
  cveId: string;
  vendorProject: string;
  product: string;
  vulnerabilityName: string;
  shortDescription: string;
  requiredAction: string;
  notes: string;
  cwes: string[];
  ransomwareUse: boolean;
  dateAdded?: string;
  dueDate?: string;
  epss?: EpssScore;
}

export interface KevCatalogSnapshot {
  fetchedAt: number;
  records: KevRecord[];
}

export interface KevSearchResult {
  cveId: string;
  vendor: string;
  product: string;
  name: string;
  dateAdded?: string;
  dueDate?: string;
  ransomwareUse: boolean;
  isOverdue: boolean;
  epssScore: number;
  epssPercentile: number;
  shortDescription: string;
}

export interface KevStats {
  totalCves: number;
  ransomwareCount: number;
  overdueCount: number;
  topVendors: Array<{ vendor: string; count: number }>;
  topCwes: Array<{ cwe: string; count: number }>;
}

export interface CveDetails {
  found: boolean;
  cveId: string;
  vendor?: string;
  product?: string;
  name?: string;
  description?: string;
  dateAdded?: string;
  dueDate?: string;
  requiredAction?: string;
  notes?: string;
  cwes?: string[];
  ransomwareUse?: boolean;
  isOverdue?: boolean;
  epssScore?: number;
  epssPercentile?: number;
  nvdUrl?: string;
  cvssPrimary?: CvssMetric;
  cvssSecondary?: CvssMetric[];
  references?: PatchReference[];
}

export interface PatchStatusResult {
  cveId: string;
  hasPatch: boolean;
  advisories: AdvisoryInfo[];
  patchReferences: PatchReference[];
  references: PatchReference[];
  nvdUrl: string;
}

export interface ExploitAvailabilityResult {
  cveId: string;
  hasPublicExploit: boolean;
  exploitSignals: string[];
  references: PatchReference[];
  githubSearchUrl: string;
  exploitDbSearchUrl: string;
  nucleiSearchUrl: string;
}

export interface SelectedCveState {
  cveId: string | null;
  selectedAt: number;
}

export interface SecurityControl {
  id: string;
  family: string;
  name: string;
  description: string;
  priority: string;
  baseline: string[];
  framework: string;
}

export interface ControlSummary {
  id: string;
  name: string;
  family: string;
  priority: string;
  baseline: string[];
  description?: string;
}

export interface CisControl {
  id: string;
  title: string;
  description: string;
  ig1: boolean;
  ig2: boolean;
  ig3: boolean;
  assetType: string;
  securityFunction: string;
}

export interface CisControlSummary {
  id: string;
  title: string;
  implementationGroup: string;
  securityFunction: string;
  assetType: string;
}

export interface ControlMappingResult {
  cveId: string;
  framework: string;
  controls?: ControlSummary[];
  cisControls?: CisControlSummary[];
  rationale: string;
  confidence: number;
  found: boolean;
}

export interface ControlDetailsResult {
  found: boolean;
  control?: SecurityControl;
  cisControl?: CisControl;
}

export interface ListControlsResult {
  count: number;
  controls?: SecurityControl[];
  cisControls?: CisControl[];
}

export interface RelatedCveItem {
  cveId: string;
  vendor: string;
  product: string;
  name: string;
  similarity: string;
  cwes: string[];
  epssScore: number;
  isOverdue: boolean;
  ransomwareUse: boolean;
}

export interface RelatedCvesResult {
  query: string;
  count: number;
  relatedCves: RelatedCveItem[];
  commonCwes?: string[];
  commonVendor?: string;
}

export interface ProductRiskCount {
  product: string;
  cveCount: number;
  ransomwareCount: number;
  avgEpss: number;
}

export interface VendorRiskProfile {
  vendor: string;
  found: boolean;
  totalCves?: number;
  ransomwareCves?: number;
  overdueCves?: number;
  averageEpss?: number;
  maxEpss?: number;
  riskScore?: number;
  riskLevel?: string;
  topProducts?: ProductRiskCount[];
  topCwes?: string[];
  recentCves?: KevSearchResult[];
  oldestUnpatched?: string;
}

export interface BatchCveAnalysis {
  cveId: string;
  found: boolean;
  vendor?: string;
  product?: string;
  name?: string;
  epssScore?: number;
  epssPercentile?: number;
  isOverdue?: boolean;
  daysOverdue?: number;
  ransomwareUse?: boolean;
  cwes?: string[];
  riskPriority?: string;
}

export interface BatchAnalyzeResult {
  count: number;
  found: number;
  notFound: string[];
  cves: BatchCveAnalysis[];
  summary: {
    totalAnalyzed: number;
    overdueCount: number;
    ransomwareCount: number;
    avgEpss: number;
    maxEpss: number;
    criticalPriority: number;
    highPriority: number;
    mediumPriority: number;
    lowPriority: number;
    commonVendors: string[];
    commonCwes: string[];
  };
}

export interface AnalyzeCweResult {
  cwe: string;
  cweName?: string;
  found: boolean;
  totalCves?: number;
  ransomwareCves?: number;
  overdueCves?: number;
  averageEpss?: number;
  affectedVendors?: Array<{ vendor: string; count: number }>;
  affectedProducts?: string[];
  cves?: KevSearchResult[];
  mitigations?: string[];
}

export interface TrendWeeklyCount {
  week: string;
  count: number;
}

export interface TrendAnalysisResult {
  period: string;
  totalCves: number;
  newCvesPerWeek: TrendWeeklyCount[];
  topVendors: Array<{ vendor: string; count: number; change?: string }>;
  topCwes: Array<{ cwe: string; name?: string; count: number }>;
  ransomwareTrend: {
    total: number;
    percentage: number;
  };
  riskTrend: string;
}
