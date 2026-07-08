import { useState, useEffect, useRef } from "react";
import { useParams, useNavigate } from "react-router-dom";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { ArrowLeft, Globe, Shield, Monitor, Loader2 } from "lucide-react";
import { listEASMScans, getEASMAssets, getEASMFindings } from "@/api/client";
import type { EASMScan, EASMAsset, EASMFinding } from "@/types";
import { toast } from "sonner";
import SeverityBadge from "@/components/SeverityBadge";

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
  const [loading, setLoading] = useState(true);
  const [tab, setTab] = useState<"assets" | "findings" | "overview">("overview");
  const pollRef = useRef<ReturnType<typeof setInterval> | null>(null);

  useEffect(() => {
    if (!id) return;
    loadData(parseInt(id));
    pollRef.current = setInterval(() => { if (id) loadData(parseInt(id)); }, 5000);
    return () => { if (pollRef.current) clearInterval(pollRef.current); };
  }, [id]);

  async function loadData(scanId: number) {
    try {
      const [scans, assetsData, findingsData] = await Promise.all([
        listEASMScans(),
        getEASMAssets(scanId),
        getEASMFindings(scanId).catch(() => []),
      ]);
      const s = scans.find((x: EASMScan) => x.id === scanId) || null;
      setScan(s);
      setAssets(assetsData);
      if (findingsData) setFindings(findingsData);
      if (s && (s.status === "completed" || s.status === "failed")) {
        if (pollRef.current) clearInterval(pollRef.current);
      }
    } catch { /* poll retries */ } finally { setLoading(false); }
  }

  if (loading) {
    return <div className="flex items-center justify-center p-20"><Loader2 className="h-6 w-6 animate-spin text-[#3B82F6]" /></div>;
  }

  if (!scan) {
    return <div className="p-6"><p className="text-[#94A3B8]">Scan not found</p><Button onClick={() => navigate("/easm")} variant="outline" size="sm" className="mt-3">Back</Button></div>;
  }

  const isRunning = scan.status === "running";
  const pct = estimateProgress(scan);
  const label = progressLabel(scan);

  return (
    <div className="space-y-3 p-3 md:p-4 lg:p-5 xl:p-6">
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

      {tab === "assets" && (
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
                </tr></thead>
                <tbody>
                  {assets.map((a) => (
                    <tr key={a.id} className="border-b border-[#1E293B] hover:bg-[#1E293B]/50">
                      <td className="p-2 text-[#F8FAFC]">{a.hostname}</td>
                      <td className="p-2 text-[#94A3B8]">{a.ip_address || "-"}</td>
                      <td className="p-2 text-[#94A3B8]">{a.cname || "-"}</td>
                      <td className="p-2">{a.is_alive ? <span className="text-green-400">● Alive</span> : <span className="text-[#64748B]">○</span>}</td>
                      <td className="p-2 text-[#94A3B8]">{a.source}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </CardContent>
        </Card>
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
  );
}
