import { useParams, useNavigate } from "react-router-dom";
import { useQuery } from "@tanstack/react-query";
import { useState, useMemo, Fragment } from "react";
import axios from "axios";
import { Card, CardContent } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import {
  ArrowLeft, Download, RefreshCw,
  AlertTriangle, Shield, Globe, Server,
  FileText, Layers,
  ChevronDown, ChevronRight, ExternalLink,
} from "lucide-react";
import PageContainer, { colSpan } from "@/components/PageContainer";
import { formatDate } from "@/lib/utils";

// ============================================================================
// Types
// ============================================================================

interface ScanDetailRecord {
  id: number;
  target: string;
  started_at: string;
  duration: string;
  ports_found: number;
  findings: number;
  risk_score: number;
  status: string;
  critical: number;
  high: number;
  medium: number;
  low: number;
  info: number;
  result?: ScanResultData;
}

interface ScanResultData {
  target?: { Raw?: string; Hosts?: string[] };
  open_ports?: PortEntry[];
  findings?: FindingEntry[];
  risk_score?: number;
  tls_info?: any;
}

interface PortEntry {
  port: number;
  protocol?: string;
  service?: string;
  product?: string;
  version?: string;
  banner?: string;
  confidence?: number;
  cpes?: { cpe_2_3_uri?: string }[];
}

interface FindingEntry {
  host?: string;
  ip?: string;
  port?: { port?: number; service?: string; protocol?: string; product?: string; version?: string };
  cve?: {
    id?: string;
    description?: string;
    cvss_v3?: number;
    cvss_v2?: number;
    severity?: string;
    is_in_kev?: boolean;
    epss_score?: number;
    epss_percentile?: number;
    references?: string[];
  };
  matched_cpe?: { cpe_2_3_uri?: string; vendor?: string; product?: string; version?: string };
  match_confidence?: number;
  match_type?: string;
  match_evidence?: string;
  detected_version?: string;
  version_validation?: string;
  version_match_result?: string;
  affected_version_range?: string;
}

// ============================================================================
// Helpers
// ============================================================================

const severityColor: Record<string, string> = {
  CRITICAL: "#EF4444",
  HIGH: "#F59E0B",
  MEDIUM: "#3B82F6",
  LOW: "#22C55E",
  NONE: "#94A3B8",
};

const severityBg: Record<string, string> = {
  CRITICAL: "rgba(239,68,68,0.12)",
  HIGH: "rgba(245,158,11,0.12)",
  MEDIUM: "rgba(59,130,246,0.12)",
  LOW: "rgba(34,197,94,0.12)",
  NONE: "rgba(148,163,184,0.08)",
};

function sevOrder(s: string) {
  return s === "CRITICAL" ? 4 : s === "HIGH" ? 3 : s === "MEDIUM" ? 2 : s === "LOW" ? 1 : 0;
}

function cvssScore(f: FindingEntry): number {
  return f.cve?.cvss_v3 ?? f.cve?.cvss_v2 ?? 0;
}

function riskLabel(score: number): { label: string; color: string } {
  if (score >= 80) return { label: "Critical", color: "#EF4444" };
  if (score >= 60) return { label: "High", color: "#F59E0B" };
  if (score >= 40) return { label: "Medium", color: "#3B82F6" };
  if (score >= 20) return { label: "Low", color: "#22C55E" };
  return { label: "None", color: "#94A3B8" };
}

// ============================================================================
// Main Page
// ============================================================================

export default function ScanDetailPage() {
  const { scanId } = useParams<{ scanId: string }>();
  const navigate = useNavigate();
  const [activeTab, setActiveTab] = useState("overview");
  const [expandedCve, setExpandedCve] = useState<string | null>(null);

  const { data: scan, isLoading, error } = useQuery({
    queryKey: ["scan-detail", scanId],
    queryFn: async () => {
      const { data } = await axios.get(`/api/scan-detail?id=${scanId}`);
      return data as ScanDetailRecord;
    },
    enabled: !!scanId,
  });

  const result = scan?.result;
  const findings = useMemo(() => {
    const raw = result?.findings ?? [];
    return [...raw].sort((a, b) => sevOrder(b.cve?.severity ?? "") - sevOrder(a.cve?.severity ?? ""));
  }, [result?.findings]);

  const ports = result?.open_ports ?? [];

  // Count severity distribution
  const sevCounts = useMemo(() => {
    const c: Record<string, number> = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, NONE: 0 };
    for (const f of findings) {
      const s = f.cve?.severity ?? "NONE";
      c[s] = (c[s] ?? 0) + 1;
    }
    return c;
  }, [findings]);

  // Top affected products
  const topProducts = useMemo(() => {
    const m = new Map<string, number>();
    for (const f of findings) {
      const p = f.port?.product || f.port?.service || "unknown";
      m.set(p, (m.get(p) ?? 0) + 1);
    }
    return [...m.entries()].sort((a, b) => b[1] - a[1]).slice(0, 5);
  }, [findings]);

  if (isLoading) {
    return (
      <PageContainer>
        <div className={colSpan(12)}>
          <div className="flex items-center justify-center py-20">
            <div className="h-8 w-8 animate-spin rounded-full border-4 border-[#3B82F6] border-t-transparent" />
          </div>
        </div>
      </PageContainer>
    );
  }

  if (error || !scan) {
    return (
      <PageContainer>
        <div className={colSpan(12)}>
          <Card className="border-[#EF4444]/30 bg-[#1E293B]">
            <CardContent className="pt-6">
              <p className="text-[#EF4444]">Scan not found</p>
              <Button onClick={() => navigate("/scan-history")} variant="outline" size="sm" className="mt-2 border-[#0B1220]">
                Back to Scan History
              </Button>
            </CardContent>
          </Card>
        </div>
      </PageContainer>
    );
  }

  const risk = riskLabel(scan.risk_score);

  const tabs = [
    { key: "overview", label: "Overview", icon: Shield },
    { key: "vulnerabilities", label: "Vulnerabilities", icon: AlertTriangle, count: findings.length },
    { key: "services", label: "Services", icon: Server, count: ports.length },
    { key: "evidence", label: "Evidence", icon: FileText },
    { key: "logs", label: "Logs", icon: Layers },
  ];

  return (
    <PageContainer>
      <div className={colSpan(12)}>

        {/* Header */}
        <div className="flex items-center justify-between mb-6">
          <div className="flex items-center gap-3">
            <Button variant="ghost" size="sm" onClick={() => navigate("/scan-history")} className="text-[#94A3B8] hover:text-[#F8FAFC]">
              <ArrowLeft className="h-4 w-4 mr-1" /> Back
            </Button>
            <div>
              <h1 className="text-xl font-bold text-[#F8FAFC]">{scan.target}</h1>
              <p className="text-xs text-[#94A3B8]">Scan #{scan.id}</p>
            </div>
          </div>
          <div className="flex gap-2">
            <Button
              variant="outline"
              size="sm"
              className="border-[#1E293B] text-[#94A3B8]"
              onClick={() => {
                const a = document.createElement("a");
                a.href = `/api/report?scan_id=${scan.id}&format=html`;
                a.download = `surfaceguard-report-${scan.target}.html`;
                a.target = "_blank";
                a.rel = "noopener noreferrer";
                a.style.display = "none";
                document.body.appendChild(a);
                a.click();
                setTimeout(() => document.body.removeChild(a), 5000);
              }}
            >
              <Download className="h-4 w-4 mr-1" /> Report
            </Button>
          </div>
        </div>

        {/* Summary Cards */}
        <div className="grid grid-cols-8 gap-4 mb-6">
          <div className="col-span-2 bg-[#1E293B] rounded-lg border border-[#1E293B] p-4">
            <p className="text-xs text-[#94A3B8] mb-1">Risk Score</p>
            <p className="text-2xl font-bold" style={{ color: risk.color }}>{scan.risk_score.toFixed(0)}</p>
            <p className="text-xs" style={{ color: risk.color }}>{risk.label}</p>
          </div>
          <SummaryCard label="Status" value={scan.status} />
          <SummaryCard label="Open Ports" value={String(scan.ports_found)} />
          <SummaryCard label="Services" value={String(ports.length)} />
          <SummaryCard label="Findings" value={String(scan.findings)} />
          <div className="col-span-2 bg-[#1E293B] rounded-lg border border-[#1E293B] p-4">
            <p className="text-xs text-[#94A3B8] mb-1">Timing</p>
            <p className="text-sm text-[#F8FAFC]">{formatDate(scan.started_at)}</p>
            <p className="text-xs text-[#94A3B8]">Duration: {scan.duration}</p>
          </div>
        </div>

        {/* Tabs */}
        <div className="flex gap-1 border-b border-[#1E293B] mb-6">
          {tabs.map((tab) => (
            <button
              key={tab.key}
              onClick={() => setActiveTab(tab.key)}
              className={`flex items-center gap-2 px-4 py-3 text-sm font-medium border-b-2 transition-colors ${
                activeTab === tab.key
                  ? "border-[#3B82F6] text-[#3B82F6]"
                  : "border-transparent text-[#94A3B8] hover:text-[#F8FAFC]"
              }`}
            >
              <tab.icon className="h-4 w-4" />
              {tab.label}
              {tab.count !== undefined && (
                <span className="bg-[#0B1220] text-[#94A3B8] text-xs px-2 py-0.5 rounded-full">{tab.count}</span>
              )}
            </button>
          ))}
        </div>

        {/* Tab Content */}
        {activeTab === "overview" && (
          <OverviewTab sevCounts={sevCounts} findings={findings} ports={ports} topProducts={topProducts} risk={risk} scan={scan} />
        )}
        {activeTab === "vulnerabilities" && (
          <VulnerabilitiesTab findings={findings} expandedCve={expandedCve} setExpandedCve={setExpandedCve} />
        )}
        {activeTab === "services" && <ServicesTab ports={ports} />}
        {activeTab === "evidence" && <EvidenceTab findings={findings} ports={ports} />}
        {activeTab === "logs" && <LogsTab scanId={scan.id} />}

      </div>
    </PageContainer>
  );
}

// ============================================================================
// Sub-components
// ============================================================================

function SummaryCard({ label, value }: { label: string; value: string }) {
  return (
    <div className="bg-[#1E293B] rounded-lg border border-[#1E293B] p-4">
      <p className="text-xs text-[#94A3B8] mb-1">{label}</p>
      <p className="text-lg font-semibold text-[#F8FAFC]">{value}</p>
    </div>
  );
}

function SeverityBadge({ severity }: { severity: string }) {
  const color = severityColor[severity] ?? "#94A3B8";
  const bg = severityBg[severity] ?? "rgba(148,163,184,0.08)";
  return (
    <span className="inline-flex px-2 py-0.5 rounded text-xs font-semibold" style={{ color, backgroundColor: bg }}>
      {severity}
    </span>
  );
}

// ============================================================================
// Overview Tab
// ============================================================================

function OverviewTab({
  sevCounts, findings, ports, topProducts, risk, scan,
}: {
  sevCounts: Record<string, number>;
  findings: FindingEntry[];
  ports: PortEntry[];
  topProducts: [string, number][];
  risk: { label: string; color: string };
  scan: ScanDetailRecord;
}) {
  const total = findings.length || 1;
  const pieSegments = [
    { label: "Critical", key: "CRITICAL", count: sevCounts.CRITICAL, color: "#EF4444" },
    { label: "High", key: "HIGH", count: sevCounts.HIGH, color: "#F59E0B" },
    { label: "Medium", key: "MEDIUM", count: sevCounts.MEDIUM, color: "#3B82F6" },
    { label: "Low", key: "LOW", count: sevCounts.LOW, color: "#22C55E" },
    { label: "None", key: "NONE", count: sevCounts.NONE, color: "#94A3B8" },
  ];

  // Service port summary
  const serviceCounts: Record<string, number> = {};
  for (const p of ports) {
    const s = p.service || "unknown";
    serviceCounts[s] = (serviceCounts[s] ?? 0) + 1;
  }

  return (
    <div className="grid grid-cols-12 gap-6">
      {/* Severity Pie */}
      <Card className="col-span-4 border-[#1E293B] bg-[#1E293B]">
        <CardContent className="pt-6">
          <h3 className="text-sm font-semibold text-[#F8FAFC] mb-4">Severity Distribution</h3>
          <div className="flex flex-col gap-2">
            {pieSegments.map((s) => (
              <div key={s.key} className="flex items-center gap-3">
                <div className="w-3 h-3 rounded-full" style={{ backgroundColor: s.color }} />
                <span className="text-xs text-[#94A3B8] w-16">{s.label}</span>
                <div className="flex-1 h-2 bg-[#0B1220] rounded-full overflow-hidden">
                  <div className="h-full rounded-full transition-all" style={{ width: `${(s.count / total) * 100}%`, backgroundColor: s.color }} />
                </div>
                <span className="text-xs text-[#F8FAFC] w-8 text-right font-medium">{s.count}</span>
              </div>
            ))}
          </div>
        </CardContent>
      </Card>

      {/* Risk Summary */}
      <Card className="col-span-4 border-[#1E293B] bg-[#1E293B]">
        <CardContent className="pt-6">
          <h3 className="text-sm font-semibold text-[#F8FAFC] mb-4">Risk Summary</h3>
          <div className="text-center py-4">
            <div className="text-4xl font-bold mb-1" style={{ color: risk.color }}>{scan.risk_score.toFixed(0)}</div>
            <p className="text-sm" style={{ color: risk.color }}>{risk.label}</p>
          </div>
          <div className="grid grid-cols-2 gap-2 mt-4">
            <div className="bg-[#0B1220] rounded p-2 text-center">
              <p className="text-lg font-bold text-[#F8FAFC]">{scan.critical}</p>
              <p className="text-xs text-[#94A3B8]">Critical</p>
            </div>
            <div className="bg-[#0B1220] rounded p-2 text-center">
              <p className="text-lg font-bold text-[#F8FAFC]">{scan.high}</p>
              <p className="text-xs text-[#94A3B8]">High</p>
            </div>
          </div>
        </CardContent>
      </Card>

      {/* Findings Stats */}
      <Card className="col-span-4 border-[#1E293B] bg-[#1E293B]">
        <CardContent className="pt-6">
          <h3 className="text-sm font-semibold text-[#F8FAFC] mb-4">Finding Statistics</h3>
          <div className="grid grid-cols-2 gap-2">
            <StatBox label="Total CVEs" value={String(scan.findings)} />
            <StatBox label="Open Ports" value={String(scan.ports_found)} />
            <StatBox label="Services" value={String(ports.length)} />
            <StatBox label="Duration" value={scan.duration} />
          </div>
        </CardContent>
      </Card>

      {/* Port Summary */}
      <Card className="col-span-6 border-[#1E293B] bg-[#1E293B]">
        <CardContent className="pt-6">
          <h3 className="text-sm font-semibold text-[#F8FAFC] mb-4">Port & Service Summary</h3>
          <div className="space-y-1.5">
            {Object.entries(serviceCounts).sort((a, b) => b[1] - a[1]).slice(0, 10).map(([svc, cnt]) => (
              <div key={svc} className="flex items-center justify-between py-1 px-2 rounded hover:bg-[#0B1220]">
                <span className="text-sm text-[#F8FAFC]">{svc}</span>
                <span className="text-xs text-[#94A3B8]">{cnt} port{cnt > 1 ? "s" : ""}</span>
              </div>
            ))}
          </div>
        </CardContent>
      </Card>

      {/* Top Products */}
      <Card className="col-span-6 border-[#1E293B] bg-[#1E293B]">
        <CardContent className="pt-6">
          <h3 className="text-sm font-semibold text-[#F8FAFC] mb-4">Top Affected Products</h3>
          <div className="space-y-1.5">
            {topProducts.map(([prod, cnt]) => (
              <div key={prod} className="flex items-center justify-between py-1 px-2 rounded hover:bg-[#0B1220]">
                <span className="text-sm text-[#F8FAFC]">{prod}</span>
                <span className="text-xs text-[#94A3B8]">{cnt} CVE{cnt > 1 ? "s" : ""}</span>
              </div>
            ))}
            {topProducts.length === 0 && <p className="text-sm text-[#94A3B8]">No findings</p>}
          </div>
        </CardContent>
      </Card>
    </div>
  );
}

function StatBox({ label, value }: { label: string; value: string }) {
  return (
    <div className="bg-[#0B1220] rounded p-3 text-center">
      <p className="text-lg font-bold text-[#F8FAFC]">{value}</p>
      <p className="text-xs text-[#94A3B8]">{label}</p>
    </div>
  );
}

// ============================================================================
// Vulnerabilities Tab
// ============================================================================

function VulnerabilitiesTab({
  findings, expandedCve, setExpandedCve,
}: {
  findings: FindingEntry[];
  expandedCve: string | null;
  setExpandedCve: (id: string | null) => void;
}) {
  if (findings.length === 0) {
    return (
      <Card className="border-[#1E293B] bg-[#1E293B]">
        <CardContent className="flex items-center justify-center py-16 text-[#94A3B8]">
          <div className="text-center">
            <Shield className="h-12 w-12 mx-auto opacity-20 mb-3" />
            <p>No vulnerabilities found</p>
          </div>
        </CardContent>
      </Card>
    );
  }

  return (
    <Card className="border-[#1E293B] bg-[#1E293B]">
      <CardContent className="pt-4 p-0">
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-[#0B1220]">
                <th className="text-left text-[#94A3B8] font-medium px-4 py-3 w-8"></th>
                <th className="text-left text-[#94A3B8] font-medium px-4 py-3">Severity</th>
                <th className="text-left text-[#94A3B8] font-medium px-4 py-3">CVE</th>
                <th className="text-left text-[#94A3B8] font-medium px-4 py-3">Product</th>
                <th className="text-left text-[#94A3B8] font-medium px-4 py-3">Port</th>
                <th className="text-left text-[#94A3B8] font-medium px-4 py-3">CVSS</th>
                <th className="text-left text-[#94A3B8] font-medium px-4 py-3">Confidence</th>
                <th className="text-left text-[#94A3B8] font-medium px-4 py-3">Status</th>
              </tr>
            </thead>
            <tbody>
              {findings.map((f, i) => {
                const cveId = f.cve?.id ?? `finding-${i}`;
                const isExpanded = expandedCve === cveId;
                return (
                  <Fragment key={cveId}>
                    <tr
                      className="border-b border-[#0B1220] hover:bg-[#0B1220] cursor-pointer transition-colors"
                      onClick={() => setExpandedCve(isExpanded ? null : cveId)}
                    >
                      <td className="px-4 py-3 text-[#94A3B8]">
                        {isExpanded ? <ChevronDown className="h-4 w-4" /> : <ChevronRight className="h-4 w-4" />}
                      </td>
                      <td className="px-4 py-3"><SeverityBadge severity={f.cve?.severity ?? "NONE"} /></td>
                      <td className="px-4 py-3">
                        <a
                          href={`https://nvd.nist.gov/vuln/detail/${cveId}`}
                          target="_blank"
                          rel="noopener noreferrer"
                          className="text-[#3B82F6] hover:underline flex items-center gap-1"
                          onClick={(e) => e.stopPropagation()}
                        >
                          {cveId} <ExternalLink className="h-3 w-3" />
                        </a>
                      </td>
                      <td className="px-4 py-3 text-[#F8FAFC]">{f.port?.product || f.port?.service || "-"}</td>
                      <td className="px-4 py-3 text-[#F8FAFC]">{f.port?.port ?? "-"}</td>
                      <td className="px-4 py-3 text-[#F8FAFC]">{cvssScore(f) ? cvssScore(f).toFixed(1) : "-"}</td>
                      <td className="px-4 py-3 text-[#F8FAFC]">{f.match_confidence ?? "-"}</td>
                      <td className="px-4 py-3">
                        <span className={`text-xs ${f.version_validation === "affected" ? "text-[#22C55E]" : f.version_validation === "not_affected" ? "text-[#EF4444]" : "text-[#94A3B8]"}`}>
                          {f.version_validation || "unknown"}
                        </span>
                      </td>
                    </tr>
                    {isExpanded && (
                      <tr className="bg-[#0B1220]">
                        <td colSpan={8} className="px-6 py-4">
                          <ExpandedFinding finding={f} />
                        </td>
                      </tr>
                    )}
                  </Fragment>
                );
              })}
            </tbody>
          </table>
        </div>
      </CardContent>
    </Card>
  );
}

// ============================================================================
// Expanded Finding Details
// ============================================================================

function ExpandedFinding({ finding }: { finding: FindingEntry }) {
  const cve = finding.cve ?? {};
  const matchedCpe = finding.matched_cpe ?? {};

  return (
    <div className="grid grid-cols-2 gap-6">
      <div className="space-y-4">
        <div>
          <h4 className="text-xs font-semibold text-[#94A3B8] uppercase tracking-wider mb-1">Description</h4>
          <p className="text-sm text-[#F8FAFC] leading-relaxed">{cve.description || "No description available"}</p>
        </div>

        <div className="grid grid-cols-2 gap-4">
          <div>
            <h4 className="text-xs font-semibold text-[#94A3B8] uppercase tracking-wider mb-1">Affected Product</h4>
            <p className="text-sm text-[#F8FAFC]">{finding.port?.product || finding.port?.service || "-"}</p>
          </div>
          <div>
            <h4 className="text-xs font-semibold text-[#94A3B8] uppercase tracking-wider mb-1">Detected Version</h4>
            <p className="text-sm text-[#F8FAFC]">{finding.detected_version || "Not detected"}</p>
          </div>
          <div>
            <h4 className="text-xs font-semibold text-[#94A3B8] uppercase tracking-wider mb-1">Fingerprint Confidence</h4>
            <p className="text-sm text-[#F8FAFC]">{finding.match_confidence ?? "-"} / 100</p>
          </div>
          <div>
            <h4 className="text-xs font-semibold text-[#94A3B8] uppercase tracking-wider mb-1">Version Match</h4>
            <p className="text-sm text-[#F8FAFC]">{finding.version_match_result || "unknown"}</p>
          </div>
        </div>

        {matchedCpe.cpe_2_3_uri && (
          <div>
            <h4 className="text-xs font-semibold text-[#94A3B8] uppercase tracking-wider mb-1">Generated CPE</h4>
            <code className="text-xs text-[#3B82F6] break-all">{matchedCpe.cpe_2_3_uri}</code>
          </div>
        )}

        {finding.match_evidence && (
          <div>
            <h4 className="text-xs font-semibold text-[#94A3B8] uppercase tracking-wider mb-1">Match Evidence</h4>
            <p className="text-sm text-[#94A3B8]">{finding.match_evidence}</p>
          </div>
        )}
      </div>

      <div className="space-y-4">
        <div className="grid grid-cols-2 gap-4">
          <DetailBox label="CVSSv3" value={cve.cvss_v3 !== undefined && cve.cvss_v3 !== null ? cve.cvss_v3.toFixed(1) : "-"} />
          <DetailBox label="CVSSv2" value={cve.cvss_v2 !== undefined && cve.cvss_v2 !== null ? cve.cvss_v2.toFixed(1) : "-"} />
          <DetailBox
            label="EPSS"
            value={cve.epss_score !== undefined && cve.epss_score !== null ? `${(cve.epss_score * 100).toFixed(1)}%` : "-"}
          />
          <DetailBox label="CISA KEV" value={cve.is_in_kev ? "Yes" : "No"} valueColor={cve.is_in_kev ? "#EF4444" : undefined} />
        </div>

        {finding.affected_version_range && (
          <div>
            <h4 className="text-xs font-semibold text-[#94A3B8] uppercase tracking-wider mb-1">Affected Version Range</h4>
            <p className="text-sm text-[#F8FAFC]">{finding.affected_version_range}</p>
          </div>
        )}

        {cve.references && cve.references.length > 0 && (
          <div>
            <h4 className="text-xs font-semibold text-[#94A3B8] uppercase tracking-wider mb-1">References</h4>
            <div className="space-y-1">
              {cve.references.slice(0, 5).map((ref, i) => (
                <a key={i} href={ref} target="_blank" rel="noopener noreferrer" className="block text-xs text-[#3B82F6] hover:underline truncate">
                  {ref}
                </a>
              ))}
            </div>
          </div>
        )}

        <div>
          <h4 className="text-xs font-semibold text-[#94A3B8] uppercase tracking-wider mb-1">Recommendation</h4>
          <p className="text-sm text-[#F8FAFC]">
            {cve.is_in_kev
              ? "This vulnerability is known to be exploited in the wild. Apply the vendor patch immediately."
              : `Update ${finding.port?.product || "the affected software"} to the latest available version.`}
          </p>
        </div>
      </div>
    </div>
  );
}

function DetailBox({ label, value, valueColor }: { label: string; value: string; valueColor?: string }) {
  return (
    <div className="bg-[#1E293B] rounded p-3">
      <p className="text-xs text-[#94A3B8] mb-0.5">{label}</p>
      <p className="text-sm font-semibold" style={{ color: valueColor ?? "#F8FAFC" }}>{value}</p>
    </div>
  );
}

// ============================================================================
// Services Tab
// ============================================================================

function ServicesTab({ ports }: { ports: PortEntry[] }) {
  if (ports.length === 0) {
    return (
      <Card className="border-[#1E293B] bg-[#1E293B]">
        <CardContent className="flex items-center justify-center py-16 text-[#94A3B8]">
          <div className="text-center">
            <Server className="h-12 w-12 mx-auto opacity-20 mb-3" />
            <p>No services detected</p>
          </div>
        </CardContent>
      </Card>
    );
  }

  return (
    <Card className="border-[#1E293B] bg-[#1E293B]">
      <CardContent className="pt-4 p-0">
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-[#0B1220]">
                <th className="text-left text-[#94A3B8] font-medium px-4 py-3">Port</th>
                <th className="text-left text-[#94A3B8] font-medium px-4 py-3">Protocol</th>
                <th className="text-left text-[#94A3B8] font-medium px-4 py-3">Service</th>
                <th className="text-left text-[#94A3B8] font-medium px-4 py-3">Product</th>
                <th className="text-left text-[#94A3B8] font-medium px-4 py-3">Version</th>
                <th className="text-left text-[#94A3B8] font-medium px-4 py-3">Confidence</th>
                <th className="text-left text-[#94A3B8] font-medium px-4 py-3">CPE</th>
                <th className="text-left text-[#94A3B8] font-medium px-4 py-3">Banner</th>
              </tr>
            </thead>
            <tbody>
              {ports.map((p, i) => (
                <tr key={i} className="border-b border-[#0B1220] hover:bg-[#0B1220]">
                  <td className="px-4 py-3 text-[#3B82F6] font-mono">{p.port}</td>
                  <td className="px-4 py-3 text-[#F8FAFC]">{p.protocol || "tcp"}</td>
                  <td className="px-4 py-3 text-[#F8FAFC]">{p.service || "-"}</td>
                  <td className="px-4 py-3 text-[#F8FAFC]">{p.product || "-"}</td>
                  <td className="px-4 py-3 text-[#F8FAFC]">{p.version || "-"}</td>
                  <td className="px-4 py-3 text-[#F8FAFC]">{p.confidence ?? "-"}</td>
                  <td className="px-4 py-3">
                    {p.cpes && p.cpes.length > 0 ? (
                      <code className="text-xs text-[#3B82F6] break-all">{p.cpes[0].cpe_2_3_uri}</code>
                    ) : (
                      <span className="text-xs text-[#94A3B8]">-</span>
                    )}
                  </td>
                  <td className="px-4 py-3 max-w-[200px]">
                    {p.banner ? (
                      <code className="text-xs text-[#94A3B8] truncate block">{p.banner.substring(0, 60)}</code>
                    ) : (
                      <span className="text-xs text-[#94A3B8]">-</span>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </CardContent>
    </Card>
  );
}

// ============================================================================
// Evidence Tab
// ============================================================================

function EvidenceTab({ findings, ports }: { findings: FindingEntry[]; ports: PortEntry[] }) {
  return (
    <div className="grid grid-cols-12 gap-6">
      <Card className="col-span-6 border-[#1E293B] bg-[#1E293B]">
        <CardContent className="pt-6">
          <h3 className="text-sm font-semibold text-[#F8FAFC] mb-4">Service Evidence</h3>
          <div className="space-y-3">
            {ports.length === 0 ? (
              <p className="text-sm text-[#94A3B8]">No service evidence collected</p>
            ) : (
              ports.slice(0, 10).map((p, i) => (
                <div key={i} className="bg-[#0B1220] rounded p-3">
                  <div className="flex items-center justify-between mb-1">
                    <span className="text-sm font-medium text-[#F8FAFC]">Port {p.port} — {p.service || "unknown"}</span>
                    <span className="text-xs text-[#94A3B8]">Confidence: {p.confidence ?? "-"}</span>
                  </div>
                  {p.product && <p className="text-xs text-[#94A3B8]">Product: {p.product} {p.version}</p>}
                  {p.banner && (
                    <div className="mt-1">
                      <p className="text-xs text-[#94A3B8] mb-0.5">Banner:</p>
                      <code className="text-xs text-[#3B82F6] break-all">{p.banner.substring(0, 200)}</code>
                    </div>
                  )}
                  {p.cpes && p.cpes.length > 0 && (
                    <div className="mt-1">
                      <p className="text-xs text-[#94A3B8] mb-0.5">CPE:</p>
                      <code className="text-xs text-[#3B82F6]">{p.cpes[0].cpe_2_3_uri}</code>
                    </div>
                  )}
                </div>
              ))
            )}
          </div>
        </CardContent>
      </Card>

      <Card className="col-span-6 border-[#1E293B] bg-[#1E293B]">
        <CardContent className="pt-6">
          <h3 className="text-sm font-semibold text-[#F8FAFC] mb-4">Finding Evidence</h3>
          <div className="space-y-3">
            {findings.length === 0 ? (
              <p className="text-sm text-[#94A3B8]">No findings to show evidence for</p>
            ) : (
              findings.slice(0, 10).map((f, i) => {
                const cveId = f.cve?.id ?? `finding-${i}`;
                return (
                  <div key={i} className="bg-[#0B1220] rounded p-3">
                    <p className="text-sm font-medium text-[#3B82F6] mb-1">{cveId}</p>
                    <div className="space-y-1 text-xs text-[#94A3B8]">
                      {f.match_type && <p>Match Type: {f.match_type}</p>}
                      {f.match_confidence !== undefined && <p>Fingerprint Confidence: {f.match_confidence}/100</p>}
                      {f.detected_version && <p>Detected Version: {f.detected_version}</p>}
                      {f.version_match_result && <p>Version Match Result: {f.version_match_result}</p>}
                      {f.version_validation && <p>Version Validation: {f.version_validation}</p>}
                      {f.affected_version_range && <p>Affected Range: {f.affected_version_range}</p>}
                      {f.match_evidence && <p>Evidence: {f.match_evidence}</p>}
                      {f.cve?.is_in_kev && <p className="text-[#EF4444]">CISA KEV: Known Exploited Vulnerability</p>}
                    </div>
                  </div>
                );
              })
            )}
          </div>
        </CardContent>
      </Card>
    </div>
  );
}

// ============================================================================
// Logs Tab
// ============================================================================

function LogsTab({ scanId }: { scanId: number }) {
  const { data: scan } = useQuery({
    queryKey: ["scan-detail", String(scanId)],
    enabled: false, // Use cached data
  });

  // Extract log-like information from the scan result.
  // In a future phase, this will display actual scan logs stored alongside results.
  const record = scan as ScanDetailRecord | undefined;

  return (
    <Card className="border-[#1E293B] bg-[#1E293B]">
      <CardContent className="pt-6">
        <div className="flex items-center justify-between mb-4">
          <h3 className="text-sm font-semibold text-[#F8FAFC]">Scan Logs</h3>
          <RefreshCw className="h-4 w-4 text-[#94A3B8]" />
        </div>
        <div className="bg-[#0B1220] rounded-lg p-4 font-mono text-xs space-y-2 max-h-96 overflow-y-auto">
          {record ? (
            <>
              <LogEntry time={record.started_at} level="INFO" message={`Scan started for target ${record.target}`} />
              <LogEntry time={record.started_at} level="INFO" message={`Scan ID: ${record.id}`} />
              <LogEntry time={record.started_at} level="INFO" message={`Ports found: ${record.ports_found}`} />
              {record.findings > 0 && (
                <LogEntry time="" level="WARN" message={`${record.findings} vulnerabilities detected`} />
              )}
              {record.critical > 0 && (
                <LogEntry time="" level="ERROR" message={`${record.critical} CRITICAL severity findings`} />
              )}
              <LogEntry time="" level="INFO" message={`Scan completed in ${record.duration}`} />
              {record.status === "completed" && (
                <LogEntry time="" level="INFO" message="Scan status: completed successfully" />
              )}
            </>
          ) : (
            <LogEntry time="" level="INFO" message="No log data available for this scan" />
          )}
        </div>
      </CardContent>
    </Card>
  );
}

function LogEntry({ time, level, message }: { time: string; level: string; message: string }) {
  const color = level === "ERROR" ? "#EF4444" : level === "WARN" ? "#F59E0B" : "#94A3B8";
  return (
    <div className="flex gap-2">
      <span className="text-[#64748B] shrink-0">{time || "---"}</span>
      <span className="shrink-0 font-semibold" style={{ color }}>[{level}]</span>
      <span className="text-[#F8FAFC]">{message}</span>
    </div>
  );
}
