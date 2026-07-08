import { useState, useEffect } from "react";
import { Card, CardContent } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { ClipboardCheck, ExternalLink, ChevronDown, ChevronUp, Trash2 } from "lucide-react";
import { getAssessmentHistory, deleteAssessmentHistory } from "@/api/client";
import type { AssessmentResult } from "@/types";
import { toast } from "sonner";

export default function AssessmentHistoryPage() {
  const [results, setResults] = useState<AssessmentResult[]>([]);
  const [loading, setLoading] = useState(true);
  const [expanded, setExpanded] = useState<Set<number>>(new Set());
  const [resetting, setResetting] = useState(false);

  useEffect(() => { loadHistory(); }, []);

  async function loadHistory() {
    try {
      const data = await getAssessmentHistory(20);
      setResults(data);
    } catch { toast.error("Failed to load assessment history"); } finally { setLoading(false); }
  }

  async function handleReset() {
    if (results.length === 0) { toast.info("No history to reset"); return; }
    if (!window.confirm("Reset all assessment history? This cannot be undone.")) return;
    setResetting(true);
    try {
      await deleteAssessmentHistory();
      toast.success("Assessment history reset");
      setResults([]);
    } catch { toast.error("Reset failed"); } finally { setResetting(false); }
  }

  function toggleExpand(id: number) {
    setExpanded((prev) => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });
  }

  function severityColor(sev: string) {
    switch (sev) {
      case "CRITICAL": return "text-red-400";
      case "HIGH": return "text-orange-400";
      case "MEDIUM": return "text-yellow-400";
      default: return "text-[#94A3B8]";
    }
  }

  return (
    <div className="space-y-3 p-3 md:p-4 lg:p-5 xl:p-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-[#F8FAFC]">Assessment History</h1>
          <p className="text-[#94A3B8] text-sm mt-1">Past authenticated assessment scans</p>
        </div>
        {results.length > 0 && (
          <Button onClick={handleReset} disabled={resetting} variant="outline" size="sm" className="border-red-500/30 text-red-400 hover:bg-red-500/10">
            <Trash2 className="h-4 w-4 mr-1" />{resetting ? "Resetting..." : "Reset"}
          </Button>
        )}
      </div>

      {loading ? (
        <p className="text-[#94A3B8]">Loading...</p>
      ) : results.length === 0 ? (
        <Card className="bg-[#111827] border-[#1E293B]">
          <CardContent className="p-8 text-center text-[#94A3B8]">
            <ClipboardCheck className="h-12 w-12 mx-auto mb-4 opacity-50" />
            <p>No assessments yet.</p>
            <p className="text-sm mt-1">Run an authenticated assessment to see results here.</p>
          </CardContent>
        </Card>
      ) : (
        <div className="space-y-3">
          {results.map((r) => (
            <Card key={r.id} className="bg-[#111827] border-[#1E293B]">
              <CardContent className="p-4">
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-3">
                    <div className={`p-2 rounded-lg ${r.protocol === "ssh" ? "bg-green-500/10" : r.protocol === "winrm" ? "bg-blue-500/10" : "bg-yellow-500/10"}`}>
                      <ClipboardCheck className={`h-5 w-5 ${r.protocol === "ssh" ? "text-green-400" : r.protocol === "winrm" ? "text-blue-400" : "text-yellow-400"}`} />
                    </div>
                    <div>
                      <h3 className="font-medium text-[#F8FAFC]">{r.asset?.hostname || r.target}</h3>
                      <p className="text-sm text-[#94A3B8]">
                        {r.target !== r.asset?.hostname && `${r.target} · `}
                        {r.protocol?.toUpperCase()} · {r.duration}
                        {r.risk_score > 0 && ` · Risk: ${r.risk_score.toFixed(0)}`}
                        {r.cves && ` · ${r.cves.length} CVEs`}
                        {r.findings && ` · ${r.findings.length} findings`}
                      </p>
                    </div>
                  </div>
                  <div className="flex items-center gap-2">
                    <Button variant="ghost" size="sm" onClick={() => toggleExpand(r.id)} className="text-[#94A3B8]">
                      {expanded.has(r.id) ? <ChevronUp className="h-4 w-4" /> : <ChevronDown className="h-4 w-4" />}
                    </Button>
                  </div>
                </div>

                {expanded.has(r.id) && (
                  <div className="mt-3 pl-14 border-t border-[#1E293B] pt-3 space-y-4">
                    {r.asset && (
                      <div className="grid grid-cols-3 gap-3 text-sm">
                        <div><span className="text-[#64748B]">Hostname:</span><span className="text-[#F8FAFC] ml-1">{r.asset.hostname}</span></div>
                        <div><span className="text-[#64748B]">OS:</span><span className="text-[#F8FAFC] ml-1">{r.asset.os}</span></div>
                        <div><span className="text-[#64748B]">Kernel:</span><span className="text-[#F8FAFC] ml-1">{r.asset.kernel_version}</span></div>
                      </div>
                    )}
                    {r.findings && r.findings.length > 0 && (
                      <div>
                        <p className="text-sm font-medium text-[#F8FAFC] mb-2">Security Findings</p>
                        <div className="space-y-1">
                          {r.findings.map((f, i) => (
                            <div key={i} className="flex items-center gap-2 text-sm">
                              <span className={`w-2 h-2 rounded-full ${f.status === "pass" ? "bg-green-500" : f.status === "warn" ? "bg-yellow-500" : "bg-red-500"}`} />
                              <span className="text-[#94A3B8]">{f.name}</span>
                              <span className={`text-xs ${severityColor(f.severity)}`}>{f.severity}</span>
                            </div>
                          ))}
                        </div>
                      </div>
                    )}
                    {r.cves && r.cves.length > 0 && (
                      <div>
                        <p className="text-sm font-medium text-[#F8FAFC] mb-2">CVEs</p>
                        <div className="flex flex-wrap gap-2">
                          {r.cves.slice(0, 10).map((cve, i) => (
                            <a key={i} href={`https://nvd.nist.gov/vuln/detail/${cve.id}`} target="_blank" rel="noopener noreferrer" className="flex items-center gap-1 px-2 py-1 bg-[#0B1220] rounded text-xs text-[#3B82F6] hover:underline">
                              {cve.id}<ExternalLink className="h-3 w-3" />
                            </a>
                          ))}
                          {r.cves.length > 10 && <span className="text-xs text-[#64748B]">+{r.cves.length - 10} more</span>}
                        </div>
                      </div>
                    )}
                    {r.packages && r.packages.length > 0 && (
                      <div>
                        <p className="text-sm font-medium text-[#F8FAFC] mb-2">Packages ({r.packages.length})</p>
                        <div className="max-h-32 overflow-y-auto">
                          <div className="grid grid-cols-3 gap-1 text-xs">
                            {r.packages.slice(0, 30).map((pkg, i) => (
                              <div key={i} className="text-[#94A3B8]">{pkg.name} <span className="text-[#64748B]">{pkg.version}</span></div>
                            ))}
                          </div>
                        </div>
                      </div>
                    )}
                  </div>
                )}
              </CardContent>
            </Card>
          ))}
        </div>
      )}
    </div>
  );
}
