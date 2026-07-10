import { useState, useEffect, useRef } from "react";
import { useParams, useNavigate } from "react-router-dom";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { ArrowLeft, Globe, Shield, Monitor, Loader2 } from "lucide-react";
import { listEASMScans, getEASMAssets, getEASMFindings, getEASMFindingsDetail, getEASMAssetDetail } from "@/api/client";
import type { EASMScan, EASMAsset, EASMFinding } from "@/types";
import { toast } from "sonner";
import SeverityBadge from "@/components/SeverityBadge";
import PageContainer, { colSpan } from "@/components/PageContainer";

function estimateProgress(scan: EASMScan): number {
  if (scan.status === "completed") return 100;
  if (scan.status === "failed") return 100;
  const alive = scan.alive_assets || 0;
  const services = scan.total_services || 0;
  if (services > 0) return 95;
  if (alive > 0) return 60 + Math.min(alive * 5, 35);
  if (scan.total_assets > 0) return 30 + Math.min(scan.total_assets * 2, 30);
  return 5;
}

function progressLabel(scan: EASMScan): string {
  if (scan.status === "completed") return "Complete";
  if (scan.status === "failed") return "Failed";
  if (scan.total_services > 0) return "Correlating CVEs...";
  if (scan.alive_assets > 0) return `Port scanning (${scan.alive_assets} assets)...`;
  if (scan.total_assets > 0) return `Resolving (${scan.total_assets} assets)...`;
  return "Discovering assets...";
}

export default function EASMScanDetail() {
  const { id } = useParams<{ id: string }>();
  const navigate = useNavigate();
  const [scan, setScan] = useState<EASMScan | null>(null);
  const [assets, setAssets] = useState<EASMAsset[]>([]);
  const [findings, setFindings] = useState<EASMFinding[]>([]);
  const [assetFindings, setAssetFindings] = useState<any[]>([]);
  const [loading, setLoading] = useState(true);
  const [tab, setTab] = useState<"assets" | "findings" | "overview">("overview");
  const [selectedAsset, setSelectedAsset] = useState<any | null>(null);
  const [assetDetail, setAssetDetail] = useState<any | null>(null);
  const [assetLoading, setAssetLoading] = useState(false);
  const pollRef = useRef<ReturnType<typeof setInterval> | null>(null);

  useEffect(() => {
    if (!id) return;
    loadData(parseInt(id));
    pollRef.current = setInterval(() => { if (id) loadData(parseInt(id)); }, 5000);
    const fallbackTimer = setTimeout(() => setLoading(false), 15000);
    return () => {
      if (pollRef.current) clearInterval(pollRef.current);
      clearTimeout(fallbackTimer);
    };
  }, [id]);

  async function loadData(scanId: number) {
    try {
      const [scans, assetsData, findingsData, assetFindingsData] = await Promise.all([
        listEASMScans(),
        getEASMAssets(scanId).catch(() => []),
        getEASMFindings(scanId).catch(() => []),
        getEASMFindingsDetail(scanId).catch(() => []),
      ]);
      const s = scans?.find((x: EASMScan) => x.id === scanId) || null;
      if (s) {
        setScan(s);
        setLoading(false);
      }
      setAssets(assetsData || []);
      setFindings(findingsData || []);
      setAssetFindings(assetFindingsData || []);
      if (s && (s.status === "completed" || s.status === "failed")) {
        if (pollRef.current) clearInterval(pollRef.current);
      }
    } catch { /* poll retries */ }
  }

  if (loading && !scan) {
    return <div className="flex items-center justify-center p-20"><Loader2 className="h-6 w-6 animate-spin text-[#3B82F6]" /></div>;
  }

  if (!scan) {
    return <div className="flex items-center justify-center p-20 space-x-2"><Loader2 className="h-5 w-5 animate-spin text-[#3B82F6]" /><span className="text-[#94A3B8] text-sm">Waiting for scan to appear...</span></div>;
  }

  const isRunning = scan.status === "running";
  const pct = estimateProgress(scan);
  const label = progressLabel(scan);

  return (
    <PageContainer>
      <div className={colSpan(12)}>
      <div className="space-y-3">
      <div className="flex items-center gap-3 mb-2">
        <Button variant="ghost" size="sm" onClick={() => navigate("/easm")} className="text-[#94A3B8] p-0"><ArrowLeft className="h-4 w-4" /></Button>
        <div className="flex-1">
          <h1 className="text-xl font-bold text-[#F8FAFC]">{scan.target}</h1>
          <p className="text-xs text-[#94A3B8]">{scan.scan_type} · {scan.wordlist} · {scan.status} · {scan.duration}</p>
        </div>
        {isRunning && <Loader2 className="h-5 w-5 animate-spin text-[#3B82F6] shrink-0" />}
      </div>

      {/* Progress bar — shown during scan */}
      {isRunning && (
        <Card className="bg-[#111827] border-[#1E293B]">
          <CardContent className="p-4">
            <div className="space-y-2">
              <div className="flex items-center justify-between text-sm">
                <div className="flex items-center gap-2">
                  <div className="w-2 h-2 rounded-full bg-[#3B82F6] animate-pulse" />
                  <span className="text-[#F8FAFC] font-medium">{label}</span>
                </div>
                <span className="text-[#3B82F6] font-bold tabular-nums">{pct}%</span>
              </div>
              <div className="w-full bg-[#0B1220] rounded-full h-2.5 overflow-hidden">
                <div className="h-full rounded-full transition-all duration-700 ease-out bg-gradient-to-r from-[#3B82F6] to-[#8B5CF6]" style={{ width: `${Math.min(pct, 100)}%` }} />
              </div>
              <p className="text-xs text-[#94A3B8]">{scan.alive_assets}/{scan.total_assets} assets · {scan.total_services} services · {scan.total_cves} CVEs</p>
            </div>
          </CardContent>
        </Card>
      )}

      {/* Summary cards */}
      <div className="grid grid-cols-5 gap-3">
        <Card className="bg-[#111827] border-[#1E293B]"><CardContent className="p-3"><p className="text-xs text-[#94A3B8]">Assets</p><p className="text-lg font-bold text-[#F8FAFC]">{scan.alive_assets}/{scan.total_assets}</p></CardContent></Card>
        <Card className="bg-[#111827] border-[#1E293B]"><CardContent className="p-3"><p className="text-xs text-[#94A3B8]">Services</p><p className="text-lg font-bold text-[#F8FAFC]">{scan.total_services}</p></CardContent></Card>
        <Card className="bg-[#111827] border-[#1E293B]"><CardContent className="p-3"><p className="text-xs text-[#94A3B8]">CVEs</p><p className="text-lg font-bold text-[#3B82F6]">{scan.total_cves}</p></CardContent></Card>
        <Card className="bg-[#111827] border-[#1E293B]"><CardContent className="p-3"><p className="text-xs text-[#94A3B8]">KEV</p><p className="text-lg font-bold text-red-400">{scan.kev_cves}</p></CardContent></Card>
        <Card className="bg-[#111827] border-[#1E293B]"><CardContent className="p-3"><p className="text-xs text-[#94A3B8]">Severity</p><p className="text-sm font-bold text-[#F8FAFC]">
          {scan.critical_cves > 0 && <span className="text-red-500 mr-1">{scan.critical_cves}C</span>}
          {scan.high_cves > 0 && <span className="text-orange-400 mr-1">{scan.high_cves}H</span>}
          {scan.medium_cves > 0 && <span className="text-yellow-400 mr-1">{scan.medium_cves}M</span>}
          {scan.low_cves > 0 && <span className="text-blue-400">{scan.low_cves}L</span>}
        </p></CardContent></Card>
      </div>

      {/* Tabs */}
      <div className="flex gap-2 border-b border-[#1E293B] pb-2">
        <button onClick={() => setTab("overview")} className={`px-3 py-1.5 text-sm rounded-md ${tab === "overview" ? "bg-[#3B82F6]/10 text-[#3B82F6]" : "text-[#94A3B8]"}`}>Overview</button>
        <button onClick={() => setTab("assets")} className={`px-3 py-1.5 text-sm rounded-md ${tab === "assets" ? "bg-[#3B82F6]/10 text-[#3B82F6]" : "text-[#94A3B8]"}`}>Assets ({assets.length})</button>
        <button onClick={() => setTab("findings")} className={`px-3 py-1.5 text-sm rounded-md ${tab === "findings" ? "bg-[#3B82F6]/10 text-[#3B82F6]" : "text-[#94A3B8]"}`}>Findings ({findings.length})</button>
      </div>

      {tab === "overview" && (
        <>
          <Card className="bg-[#111827] border-[#1E293B]">
            <CardHeader className="pb-3"><CardTitle className="text-sm text-[#F8FAFC]">Discovered Assets</CardTitle></CardHeader>
            <CardContent>
              <div className="overflow-x-auto">
                <table className="w-full text-xs">
                  <thead><tr className="border-b border-[#1E293B]">
                    <th className="text-left p-2 text-[#94A3B8]">Hostname</th>
                    <th className="text-left p-2 text-[#94A3B8]">IP</th>
                    <th className="text-left p-2 text-[#94A3B8]">Alive</th>
                    <th className="text-left p-2 text-[#94A3B8]">Source</th>
                  </tr></thead>
                  <tbody>
                    {assets.slice(0, 10).map((a) => (
                      <tr key={a.id} className="border-b border-[#1E293B]">
                        <td className="p-2 text-[#F8FAFC]">{a.hostname}</td>
                        <td className="p-2 text-[#94A3B8]">{a.ip_address || "-"}</td>
                        <td className="p-2">{a.is_alive ? <span className="text-green-400">Yes</span> : <span className="text-[#64748B]">No</span>}</td>
                        <td className="p-2 text-[#94A3B8]">{a.source}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </CardContent>
          </Card>
          <Card className="bg-[#111827] border-[#1E293B]">
            <CardHeader className="pb-3"><CardTitle className="text-sm text-[#F8FAFC]">Findings by Asset ({assetFindings.length} assets)</CardTitle></CardHeader>
            <CardContent>
              {assetFindings.length === 0 ? <p className="text-[#94A3B8] text-sm">No findings</p>
                : <div className="space-y-1.5">{assetFindings.slice(0, 10).map((g: any, i: number) => (
                    <div key={i} className="flex items-center justify-between p-2 bg-[#0B1220] rounded-lg">
                      <div className="flex-1 min-w-0">
                        <p className="text-sm font-medium text-[#F8FAFC]">{g.hostname}</p>
                        {g.ip && <p className="text-xs text-[#64748B]">{g.ip}</p>}
                      </div>
                      <div className="text-right shrink-0">
                        <p className="text-xs text-[#3B82F6] font-medium">{g.cve_count} CVEs</p>
                        <div className="flex gap-1 mt-0.5">
                          {[...new Set(g.findings.map((f: any) => f.severity))].filter(Boolean).slice(0, 3).map((s: any) => (
                            <SeverityBadge key={s} severity={s} />
                          ))}
                        </div>
                      </div>
                    </div>
                  ))}</div>}
            </CardContent>
          </Card>
          <Card className="bg-[#111827] border-[#1E293B]">
            <CardHeader className="pb-3"><CardTitle className="text-sm text-[#F8FAFC]">Top Findings</CardTitle></CardHeader>
            <CardContent>
              {findings.length === 0 ? <p className="text-[#94A3B8] text-sm">No findings</p>
                : <div className="space-y-1.5">{findings.slice(0, 10).map((f, i) => (
                    <div key={i} className="flex items-center gap-2 p-2 bg-[#0B1220] rounded-lg">
                      <div className={`w-1.5 h-1.5 rounded-full shrink-0 ${f.severity === "CRITICAL" ? "bg-red-500" : f.severity === "HIGH" ? "bg-orange-500" : f.severity === "MEDIUM" ? "bg-yellow-500" : "bg-blue-500"}`} />
                      <div className="flex-1 min-w-0">
                        <a href={`https://nvd.nist.gov/vuln/detail/${f.cve_id}`} target="_blank" rel="noopener noreferrer" className="font-medium text-xs text-[#3B82F6] hover:underline">{f.cve_id}</a>
                        <p className="text-xs text-[#94A3B8] truncate">{f.description?.substring(0, 100)}</p>
                      </div>
                      <div className="text-right shrink-0"><p className="text-xs font-medium text-[#F8FAFC]">{f.cvss_v3?.toFixed(1) || "N/A"}</p><SeverityBadge severity={f.severity} /></div>
                    </div>
                  ))}</div>}
            </CardContent>
          </Card>
        </>
      )}

      {tab === "assets" && !selectedAsset && (
        <Card className="bg-[#111827] border-[#1E293B]">
          <CardContent className="p-3">
            <div className="overflow-x-auto">
              <table className="w-full text-sm">
                <thead><tr className="border-b border-[#1E293B]">
                  <th className="text-left p-2 text-[#94A3B8]">Hostname</th>
                  <th className="text-left p-2 text-[#94A3B8]">IP</th>
                  <th className="text-left p-2 text-[#94A3B8]">CNAME</th>
                  <th className="text-left p-2 text-[#94A3B8]">Alive</th>
                  <th className="text-left p-2 text-[#94A3B8]">Source</th>
                  <th className="text-left p-2 text-[#94A3B8]">CVEs</th>
                </tr></thead>
                <tbody>
                  {assets.map((a) => (
                    <tr key={a.id} className="border-b border-[#1E293B] hover:bg-[#3B82F6]/10 cursor-pointer"
                        onClick={async () => {
                          setSelectedAsset(a);
                          setAssetLoading(true);
                          try { const d = await getEASMAssetDetail(a.id); setAssetDetail(d); } catch {} finally { setAssetLoading(false); }
                        }}>
                      <td className="p-2 text-[#3B82F6] font-medium">{a.hostname}</td>
                      <td className="p-2 text-[#94A3B8]">{a.ip_address || "-"}</td>
                      <td className="p-2 text-[#94A3B8]">{a.cname || "-"}</td>
                      <td className="p-2">{a.is_alive ? <span className="text-green-400">● Alive</span> : <span className="text-[#64748B]">○</span>}</td>
                      <td className="p-2 text-[#94A3B8]">{a.source}</td>
                      <td className="p-2">
                        <span className="text-[#3B82F6] font-medium">
                          {assetFindings.find((g: any) => g.hostname === a.hostname)?.cve_count ?? 0}
                        </span>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </CardContent>
        </Card>
      )}

      {/* Asset Detail Panel */}
      {tab === "assets" && selectedAsset && (
        <div>
          <button onClick={() => { setSelectedAsset(null); setAssetDetail(null); }} className="text-xs text-[#3B82F6] hover:underline mb-3">← Back to assets</button>
          {assetLoading ? <p className="text-[#94A3B8] text-sm">Loading...</p> : assetDetail ? (
            <>
              <div className="grid grid-cols-4 gap-3 mb-3">
                <div className="bg-[#111827] border border-[#1E293B] rounded-lg p-3">
                  <p className="text-xs text-[#94A3B8]">Hostname</p>
                  <p className="text-sm font-bold text-[#F8FAFC]">{assetDetail.hostname}</p>
                  {assetDetail.ip_address && <p className="text-xs text-[#64748B]">{assetDetail.ip_address}</p>}
                </div>
                <div className="bg-[#111827] border border-[#1E293B] rounded-lg p-3">
                  <p className="text-xs text-[#94A3B8]">Risk Score</p>
                  <p className={`text-lg font-bold ${assetDetail.risk_level === "CRITICAL" ? "text-red-500" : assetDetail.risk_level === "HIGH" ? "text-orange-400" : assetDetail.risk_level === "MEDIUM" ? "text-yellow-400" : "text-green-400"}`}>{assetDetail.risk_score.toFixed(0)}/100</p>
                  <p className="text-xs text-[#64748B]">{assetDetail.risk_level}</p>
                </div>
                <div className="bg-[#111827] border border-[#1E293B] rounded-lg p-3">
                  <p className="text-xs text-[#94A3B8]">Services</p>
                  <p className="text-lg font-bold text-[#F8FAFC]">{assetDetail.services?.length || 0}</p>
                  {assetDetail.technologies?.length > 0 && <p className="text-xs text-[#64748B]">{assetDetail.technologies.join(", ")}</p>}
                </div>
                <div className="bg-[#111827] border border-[#1E293B] rounded-lg p-3">
                  <p className="text-xs text-[#94A3B8]">Vulnerabilities</p>
                  <p className="text-lg font-bold text-[#3B82F6]">{assetDetail.cve_count}</p>
                  {assetDetail.kev_count > 0 && <p className="text-xs text-red-400">{assetDetail.kev_count} KEV</p>}
                </div>
              </div>

              {assetDetail.services?.length > 0 && (
                <Card className="bg-[#111827] border-[#1E293B] mb-3">
                  <CardHeader className="pb-3"><CardTitle className="text-sm text-[#F8FAFC]">Services ({assetDetail.services.length})</CardTitle></CardHeader>
                  <CardContent>
                    <div className="overflow-x-auto"><table className="w-full text-sm">
                      <thead><tr className="border-b border-[#1E293B]">
                        <th className="text-left p-2 text-[#94A3B8]">Port</th><th className="text-left p-2 text-[#94A3B8]">Service</th>
                        <th className="text-left p-2 text-[#94A3B8]">Product</th><th className="text-left p-2 text-[#94A3B8]">Version</th>
                        <th className="text-left p-2 text-[#94A3B8]">CPE</th>
                      </tr></thead>
                      <tbody>{assetDetail.services.map((s: any) => (
                        <tr key={s.id} className="border-b border-[#1E293B]/50">
                          <td className="p-2 font-mono text-sm text-[#F8FAFC]">{s.port}</td>
                          <td className="p-2 text-sm text-[#F8FAFC]">{s.service}</td>
                          <td className="p-2 text-sm text-[#94A3B8]">{s.product || "—"}</td>
                          <td className="p-2 text-sm text-[#94A3B8]">{s.version || "—"}</td>
                          <td className="p-2 text-xs text-[#64748B] truncate max-w-[200px]">{s.cpe_2_3_uri || "—"}</td>
                        </tr>
                      ))}</tbody>
                    </table></div>
                  </CardContent>
                </Card>
              )}

              {assetDetail.findings?.length > 0 && (
                <Card className="bg-[#111827] border-[#1E293B]">
                  <CardHeader className="pb-3"><CardTitle className="text-sm text-[#F8FAFC]">Findings ({assetDetail.cve_count})</CardTitle></CardHeader>
                  <CardContent>
                    <div className="space-y-1.5">{assetDetail.findings.slice(0, 20).map((f: any, i: number) => (
                      <div key={i} className="flex items-center gap-2.5 p-2.5 bg-[#0B1220] rounded-lg">
                        <div className={`w-1.5 h-1.5 rounded-full shrink-0 ${f.severity === "CRITICAL" ? "bg-red-500" : f.severity === "HIGH" ? "bg-orange-500" : f.severity === "MEDIUM" ? "bg-yellow-500" : "bg-blue-500"}`} />
                        <div className="flex-1 min-w-0">
                          <a href={`https://nvd.nist.gov/vuln/detail/${f.cve_id}`} target="_blank" className="font-medium text-xs text-[#3B82F6] hover:underline">{f.cve_id}</a>
                          <p className="text-xs text-[#94A3B8] truncate">{f.description?.substring(0, 120)}</p>
                        </div>
                        <div className="text-right shrink-0"><p className="text-xs font-medium text-[#F8FAFC]">{f.cvss_v3?.toFixed(1) || "N/A"}</p><SeverityBadge severity={f.severity} /></div>
                      </div>
                    ))}</div>
                  </CardContent>
                </Card>
              )}
            </>
          ) : <p className="text-[#94A3B8] text-sm">Loading asset...</p>}
        </div>
      )}

      {tab === "findings" && (
        <Card className="bg-[#111827] border-[#1E293B]">
          <CardContent className="p-3">
            {findings.length === 0 ? <p className="text-[#94A3B8] text-sm">No vulnerabilities found</p>
              : <div className="space-y-1.5">{findings.map((f, i) => (
                  <div key={i} className="flex items-center gap-2.5 p-2.5 bg-[#0B1220] rounded-lg">
                    <div className={`w-1.5 h-1.5 rounded-full shrink-0 ${f.severity === "CRITICAL" ? "bg-red-500" : f.severity === "HIGH" ? "bg-orange-500" : f.severity === "MEDIUM" ? "bg-yellow-500" : "bg-blue-500"}`} />
                    <div className="flex-1 min-w-0">
                      <a href={`https://nvd.nist.gov/vuln/detail/${f.cve_id}`} target="_blank" rel="noopener noreferrer" className="font-medium text-xs text-[#3B82F6] hover:underline">{f.cve_id}</a>
                      <p className="text-xs text-[#94A3B8]">{f.description?.substring(0, 150)}</p>
                      {f.matched_cpe && <p className="text-xs text-[#64748B] mt-0.5">CPE: {f.matched_cpe}</p>}
                    </div>
                    <div className="text-right shrink-0 space-y-0.5">
                      <p className="text-xs font-medium text-[#F8FAFC]">{f.cvss_v3?.toFixed(1) || "N/A"}</p>
                      <SeverityBadge severity={f.severity} />
                      {f.is_kev && <p className="text-xs text-red-400">⚠ KEV</p>}
                    </div>
                  </div>
                ))}</div>}
          </CardContent>
        </Card>
      )}
    </div>
    </div>
    </PageContainer>
  );
}
