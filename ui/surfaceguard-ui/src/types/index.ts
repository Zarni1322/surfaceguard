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
