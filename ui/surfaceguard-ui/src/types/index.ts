export interface DatabaseInfo {
  schema_version: number;
  last_updated: string;
  cve_count: number;
  cpe_count: number;
  product_count: number;
  vendor_count: number;
  kev_count: number;
  epss_count: number;
  integrity_ok: boolean;
}

export interface ScanTarget {
  raw: string;
  hosts: string[];
  is_cidr: boolean;
  is_ipv4: boolean;
  resolved_at: string;
}

export interface Port {
  port: number;
  protocol: string;
  service: string;
  product: string;
  version: string;
  banner: string;
  cpes: CPE[];
  state: string;
  confidence: number;
}

export interface CPE {
  part: string;
  vendor: string;
  product: string;
  version: string;
  update: string;
  edition: string;
  language: string;
  target_sw: string;
  target_hw: string;
  other: string;
  cpe_2_3_uri: string;
}

export interface CVE {
  id: string;
  description: string;
  cvss_v2: number | null;
  cvss_v3: number | null;
  severity: string;
  published_date: string;
  last_modified_date: string;
  references: string[];
  cpe_2_3_uri: string;
  is_in_kev: boolean;
  kev_due_date: string | null;
  epss_score: number | null;
  epss_percentile: number | null;
}

export interface Finding {
  host: string;
  ip: string;
  port: Port;
  cve: CVE;
  matched_cpe: CPE;
}

export interface TLSResult {
  host: string;
  port: number;
  version: string;
  certificate_cn: string;
  certificate_issuer: string;
  certificate_expiry: string;
  days_until_expiry: number;
  self_signed: boolean;
  weak_cipher: boolean;
  deprecated_protocol: boolean;
  sans: string[];
}

export interface ScanResult {
  target: ScanTarget;
  started_at: string;
  duration: string;
  open_ports: Port[];
  findings: Finding[];
  tls_info: TLSResult | null;
  risk_score: number;
  errors: string[];
}

export interface UpdateStats {
  cves_inserted: number;
  cves_updated: number;
  kev_inserted: number;
  kev_updated: number;
  epss_inserted: number;
  epss_updated: number;
  errors: string[];
}

export interface FeedStatus {
  nvd: { status: string; last_update: string; count: number };
  kev: { status: string; catalog_version: string; count: number };
  epss: { status: string; score_date: string; count: number };
}

export interface ScanHistoryItem {
  id: number;
  target: string;
  started_at: string;
  duration: string;
  ports_found: number;
  findings_count: number;
  risk_score: number;
  status: string;
}

export interface SystemInfo {
  version: string;
  build_date: string;
  db_version: string;
  feed_status: string;
  last_update: string;
}

// ============================================================================
// Authenticated Assessment Types
// ============================================================================

export interface CredentialProfile {
  id: number;
  name: string;
  protocol: string;
  host: string;
  port: number;
  username: string;
  auth_method: string;
  created_at: string;
  updated_at: string;
}

export interface ValidationCheck {
  name: string;
  status: string; // pass, warn, fail
  message?: string;
}

export interface ValidationResult {
  status: string; // SUCCESS, WARNING, FAILED
  checks: ValidationCheck[];
  tested_at: string;
  profile_id: number;
  target: string;
}

export interface AssetInfo {
  id: number;
  hostname: string;
  ip: string;
  os: string;
  distro: string;
  kernel_version: string;
  architecture: string;
  asset_type: string;
  risk_score: number;
  last_seen: string;
  last_scan: string;
}

export interface InstalledPackage {
  name: string;
  version: string;
  arch: string;
  cpe_2_3_uri: string;
  status: string;
}

export interface InstalledSoftware {
  name: string;
  version: string;
  vendor: string;
  install_date: string;
  cpe_2_3_uri: string;
}

export interface SecurityFinding {
  check_id: string;
  name: string;
  severity: string;
  status: string;
  evidence?: string;
}

export interface AssessmentResult {
  id: number;
  target: string;
  profile_id: number;
  profile_name: string;
  protocol: string;
  started_at: string;
  duration: string;
  asset?: AssetInfo;
  packages?: InstalledPackage[];
  software?: InstalledSoftware[];
  findings?: SecurityFinding[];
  cves?: CVE[];
  risk_score: number;
  validation?: ValidationResult;
  status: string;
}

// ScanProgress represents a real-time progress event from the assessment SSE endpoint.
export interface ScanProgress {
  step: string;     // connecting, collecting, packages, cves, done, failed
  progress: number; // 0.0–100.0
  message: string;  // human-readable status message
}

export interface AssetDetail {
  id: number;
  hostname: string;
  ip: string;
  os: string;
  distro: string;
  kernel_version: string;
  architecture: string;
  asset_type: string;
  risk_score: number;
  last_seen: string;
  last_scan: string;
  packages?: InstalledPackage[];
  software?: InstalledSoftware[];
}
