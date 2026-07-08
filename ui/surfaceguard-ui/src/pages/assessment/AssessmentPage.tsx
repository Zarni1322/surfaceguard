import { useState, useEffect } from "react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { ShieldCheck, Loader2, CheckCircle, XCircle, AlertTriangle } from "lucide-react";
import { listCredentialProfiles, runAssessmentScan, runAssessmentScanSSE } from "@/api/client";
import type { CredentialProfile, AssessmentResult, ScanProgress } from "@/types";
import { toast } from "sonner";
import PageHeader from "@/components/PageHeader";
import PageContainer, { colSpan } from "@/components/PageContainer";
import SeverityBadge from "@/components/SeverityBadge";

export default function AssessmentPage() {
  const [profiles, setProfiles] = useState<CredentialProfile[]>([]);
  const [loading, setLoading] = useState(true);
  const [selected, setSelected] = useState<number | null>(null);
  const [scanning, setScanning] = useState(false);
  const [result, setResult] = useState<AssessmentResult | null>(null);
  const [progress, setProgress] = useState<ScanProgress | null>(null);
  const [useSSE, setUseSSE] = useState(true);

  useEffect(() => {
    listCredentialProfiles()
      .then(setProfiles)
      .catch(() => toast.error("Failed to load profiles"))
      .finally(() => setLoading(false));
  }, []);

  async function handleScan() {
    if (!selected) return;
    setScanning(true);
    setResult(null);
    setProgress(null);

    if (useSSE) {
      // Use SSE for live progress updates.
      const cleanup = runAssessmentScanSSE(
        selected,
        (p) => setProgress(p),
        (r) => {
          setResult(r);
          setScanning(false);
          setProgress(null);
          toast.success("Assessment complete");
        },
        (err) => {
          // Fall back to polling on SSE failure.
          console.warn("SSE failed, falling back to polling:", err);
          setUseSSE(false);
          // Retry with polling.
          runAssessmentScan(selected)
            .then((r) => {
              setResult(r);
              toast.success("Assessment complete");
            })
            .catch(() => toast.error("Assessment failed"))
            .finally(() => setScanning(false));
        },
      );
      // Store cleanup if we need to cancel.
      return;
    }

    // Fallback: direct HTTP (no progress).
    try {
      const res = await runAssessmentScan(selected);
      setResult(res);
      toast.success("Assessment complete");
    } catch {
      toast.error("Assessment failed");
    } finally {
      setScanning(false);
    }
  }

  function si(status: string) {
    switch (status) {
      case "pass": return <CheckCircle className="h-3.5 w-3.5 text-green-400" />;
      case "warn": return <AlertTriangle className="h-3.5 w-3.5 text-yellow-400" />;
      case "fail": return <XCircle className="h-3.5 w-3.5 text-red-400" />;
      default: return null;
    }
  }

  // Map step names to label and color
  function stepInfo(step: string): { label: string; color: string } {
    switch (step) {
      case "starting": case "connecting": return { label: "Connecting", color: "bg-blue-500" };
      case "collecting": return { label: "Collecting data", color: "bg-indigo-500" };
      case "cves": return { label: "Correlating CVEs", color: "bg-orange-500" };
      case "scoring": return { label: "Scoring", color: "bg-yellow-500" };
      case "saving": return { label: "Saving", color: "bg-purple-500" };
      case "done": return { label: "Done", color: "bg-green-500" };
      default: return { label: step, color: "bg-gray-500" };
    }
  }

  return (
    <PageContainer>
      <div className={colSpan(12)}>
        <PageHeader title="Authenticated Assessment" description="Run credentialed scans against Linux, Windows, and network devices" />
      </div>

      <div className={colSpan(12)}>
        <Card className="bg-[#111827] border-[#1E293B]">
          <CardHeader className="pb-3"><CardTitle className="text-base text-[#F8FAFC]">Select Profile</CardTitle></CardHeader>
          <CardContent className="space-y-3">
            {loading ? <p className="text-[#94A3B8] text-sm">Loading...</p>
              : profiles.length === 0 ? <p className="text-[#94A3B8] text-sm">No profiles. Create one first.</p>
              : <div className="space-y-1.5">{profiles.map((p) => (
                  <label key={p.id} className={`flex items-center gap-3 p-2.5 rounded-lg border cursor-pointer ${selected === p.id ? "bg-[#3B82F6]/10 border-[#3B82F6]" : "bg-[#0B1220] border-[#1E293B] hover:border-[#3B82F6]/50"}`}>
                    <input type="radio" name="profile" checked={selected === p.id} onChange={() => setSelected(p.id)} className="accent-[#3B82F6]" />
                    <div><span className="font-medium text-sm text-[#F8FAFC]">{p.name}</span><span className="text-xs text-[#94A3B8] ml-2">{p.protocol.toUpperCase()} · {p.host}:{p.port}</span></div>
                  </label>
                ))}</div>}
            <Button onClick={handleScan} disabled={!selected || scanning} size="sm" className="bg-[#3B82F6]">
              {scanning ? <Loader2 className="h-4 w-4 mr-1 animate-spin" /> : <ShieldCheck className="h-4 w-4 mr-1" />}
              {scanning ? "Scanning..." : "Run Assessment"}
            </Button>
          </CardContent>
        </Card>
      </div>

      {/* Progress bar — shown during scan */}
      {scanning && progress && (
        <div className={colSpan(12)}>
          <Card className="bg-[#111827] border-[#1E293B]">
            <CardContent className="p-4">
              <div className="space-y-2">
                <div className="flex items-center justify-between text-sm">
                  <div className="flex items-center gap-2">
                    {(() => {
                      const info = stepInfo(progress.step);
                      return <><div className={`w-2 h-2 rounded-full ${info.color} animate-pulse`} /><span className="text-[#F8FAFC] font-medium">{info.label}</span></>;
                    })()}
                  </div>
                  <span className="text-[#3B82F6] font-bold tabular-nums">{Math.round(progress.progress)}%</span>
                </div>

                {/* Progress bar */}
                <div className="w-full bg-[#0B1220] rounded-full h-2.5 overflow-hidden">
                  <div
                    className="h-full rounded-full transition-all duration-500 ease-out bg-gradient-to-r from-[#3B82F6] to-[#8B5CF6]"
                    style={{ width: `${Math.min(progress.progress, 100)}%` }}
                  />
                </div>

                <p className="text-xs text-[#94A3B8]">{progress.message}</p>
              </div>
            </CardContent>
          </Card>
        </div>
      )}

      {result && (
        <>
          <div className={colSpan(12)}>
            <Card className="bg-[#111827] border-[#1E293B]">
              <CardHeader className="pb-3"><CardTitle className="text-base text-[#F8FAFC]">Assessment Results</CardTitle></CardHeader>
              <CardContent>
                <div className="grid grid-cols-3 gap-3 mb-3">
                  <div className="bg-[#0B1220] rounded-lg p-3"><p className="text-xs text-[#94A3B8]">Target</p><p className="text-sm font-semibold text-[#F8FAFC]">{result.target}</p></div>
                  <div className="bg-[#0B1220] rounded-lg p-3"><p className="text-xs text-[#94A3B8]">Duration</p><p className="text-sm font-semibold text-[#F8FAFC]">{result.duration}</p></div>
                  <div className="bg-[#0B1220] rounded-lg p-3"><p className="text-xs text-[#94A3B8]">Risk</p><p className="text-sm font-semibold text-[#F8FAFC]">{result.risk_score.toFixed(1)}/100</p></div>
                </div>
                {result.asset && <div className="grid grid-cols-3 gap-3 text-xs">{result.asset.hostname && <div><span className="text-[#64748B]">Hostname:</span><span className="text-[#F8FAFC] ml-1">{result.asset.hostname}</span></div>}<div><span className="text-[#64748B]">OS:</span><span className="text-[#F8FAFC] ml-1">{result.asset.os}</span></div><div><span className="text-[#64748B]">Kernel:</span><span className="text-[#F8FAFC] ml-1">{result.asset.kernel_version}</span></div></div>}
              </CardContent>
            </Card>
          </div>

          {result.findings && result.findings.length > 0 && (
            <div className={colSpan(12)}>
              <Card className="bg-[#111827] border-[#1E293B]">
                <CardHeader className="pb-3"><CardTitle className="text-base text-[#F8FAFC]">Security Findings ({result.findings.length})</CardTitle></CardHeader>
                <CardContent><div className="space-y-1.5">{result.findings.map((f, i) => (
                  <div key={i} className="flex items-center gap-2.5 p-2.5 bg-[#0B1220] rounded-lg">
                    {si(f.status)}<div className="flex-1 min-w-0"><div className="flex items-center gap-2"><span className="font-medium text-sm text-[#F8FAFC] truncate">{f.name}</span><SeverityBadge severity={f.severity} /></div>{f.evidence && <p className="text-xs text-[#94A3B8] truncate">{f.evidence}</p>}</div>
                  </div>
                ))}</div></CardContent>
              </Card>
            </div>
          )}

          {result.cves && result.cves.length > 0 && (
            <div className={colSpan(12)}>
              <Card className="bg-[#111827] border-[#1E293B]">
                <CardHeader className="pb-3"><CardTitle className="text-base text-[#F8FAFC]">Detected CVEs ({result.cves.length})</CardTitle></CardHeader>
                <CardContent><div className="space-y-1.5">{result.cves.map((cve, i) => (
                  <div key={i} className="flex items-center gap-2.5 p-2.5 bg-[#0B1220] rounded-lg">
                    <div className={`w-1.5 h-1.5 rounded-full shrink-0 ${cve.severity === "CRITICAL" ? "bg-red-500" : cve.severity === "HIGH" ? "bg-orange-500" : cve.severity === "MEDIUM" ? "bg-yellow-500" : "bg-blue-500"}`} />
                    <div className="flex-1 min-w-0">
                      <a href={`https://nvd.nist.gov/vuln/detail/${cve.id}`} target="_blank" rel="noopener noreferrer" className="font-medium text-xs text-[#3B82F6] hover:underline">{cve.id}</a>
                      <p className="text-xs text-[#94A3B8] truncate">{cve.description?.substring(0, 120)}</p>
                    </div>
                    <div className="text-right shrink-0"><p className="text-xs font-medium text-[#F8FAFC]">{cve.cvss_v3?.toFixed(1) || "N/A"}</p><SeverityBadge severity={cve.severity} /></div>
                  </div>
                ))}</div></CardContent>
              </Card>
            </div>
          )}
        </>
      )}
    </PageContainer>
  );
}
