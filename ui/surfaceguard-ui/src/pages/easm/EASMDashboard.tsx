import { useState, useEffect, useRef } from "react";
import { useNavigate } from "react-router-dom";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Globe, List, RefreshCw, Loader2, Activity, Trash2 } from "lucide-react";
import { listEASMScans, createEASMScan, deleteEASMScans } from "@/api/client";
import type { EASMScan } from "@/types";
import { toast } from "sonner";
import PageHeader from "@/components/PageHeader";
import PageContainer, { colSpan } from "@/components/PageContainer";
import EmptyState from "@/components/EmptyState";

export default function EASMDashboard() {
  const navigate = useNavigate();
  const [scans, setScans] = useState<EASMScan[]>([]);
  const [loading, setLoading] = useState(true);
  const [showForm, setShowForm] = useState(false);
  const [scanning, setScanning] = useState(false);
  const [form, setForm] = useState({
    target: "",
    scan_type: "domain" as string,
    wordlist: "passive" as string,
    ports: "fast" as string,
    workers: 50,
  });
  const pollRef = useRef<ReturnType<typeof setInterval> | null>(null);

  useEffect(() => {
    loadScans();
    pollRef.current = setInterval(() => { listEASMScans().then(setScans).catch(() => {}); }, 5000);
    return () => { if (pollRef.current) clearInterval(pollRef.current); };
  }, []);

  async function loadScans() {
    try { setScans(await listEASMScans()); } catch { /* ignore */ } finally { setLoading(false); }
  }

  async function handleCreate() {
    if (!form.target.trim()) { toast.error("Target is required"); return; }
    setScanning(true);
    try {
      const res = await createEASMScan({
        target: form.target,
        scan_type: form.scan_type,
        wordlist: form.wordlist,
        ports: form.ports,
        workers: form.workers,
        screenshots: false,
      } as any);
      setShowForm(false);
      if (res.scan_id) navigate(`/easm/${res.scan_id}`, { replace: true });
    } catch (e: any) {
      const msg = e?.response?.data?.error || e?.message || "Request timed out.";
      toast.error(msg);
      setScanning(false);
    }
  }

  async function handleReset() {
    if (scans.length === 0) { toast.info("No scans to reset"); return; }
    if (!window.confirm("Reset all EASM scan history? This cannot be undone.")) return;
    try {
      await deleteEASMScans();
      toast.success("EASM history reset");
      setScans([]);
    } catch { toast.error("Reset failed"); }
  }

  function statusColor(status: string) {
    switch (status) {
      case "running": return "text-blue-400";
      case "completed": return "text-green-400";
      case "failed": return "text-red-400";
      default: return "text-[#94A3B8]";
    }
  }

  function severitySummary(s: EASMScan) {
    const parts: string[] = [];
    if (s.critical_cves > 0) parts.push(`C:${s.critical_cves}`);
    if (s.high_cves > 0) parts.push(`H:${s.high_cves}`);
    if (s.medium_cves > 0) parts.push(`M:${s.medium_cves}`);
    if (s.low_cves > 0) parts.push(`L:${s.low_cves}`);
    return parts.join(" ") || "None";
  }

  return (
    <PageContainer>
      <div className={colSpan(12)}>
        <PageHeader title="External Attack Surface" description="Discover and assess externally exposed assets"
          actions={
            <div className="flex gap-2">
              <Button onClick={handleReset} variant="outline" size="sm" className="border-red-500/30 text-red-400 hover:bg-red-500/10">
                <Trash2 className="h-4 w-4 mr-1" />Reset
              </Button>
              <Button onClick={() => setShowForm(!showForm)} size="sm" className="bg-[#3B82F6]">
                <Globe className="h-4 w-4 mr-1" />EASM Scan
              </Button>
            </div>
          } />
      </div>

      {showForm && (
        <div className={colSpan(12)}>
          <Card className="border-[#1E293B] bg-[#1E293B]">
            <CardHeader className="pb-3"><CardTitle className="text-base text-[#F8FAFC]">EASM Scan</CardTitle></CardHeader>
            <CardContent className="space-y-3">
              <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
                <div className="md:col-span-2">
                  <label className="block text-xs text-[#94A3B8] mb-1">Target</label>
                  <Input value={form.target} onChange={(e) => setForm({ ...form, target: e.target.value })}
                    placeholder="example.com, 192.168.1.0/24, or 10.0.0.1" className="bg-[#0B1220] border-[#1E293B] text-[#F8FAFC] text-sm" />
                </div>
                <div>
                  <label className="block text-xs text-[#94A3B8] mb-1">Type</label>
                  <select value={form.scan_type} onChange={(e) => setForm({ ...form, scan_type: e.target.value })}
                    className="w-full bg-[#0B1220] border border-[#1E293B] rounded-md p-2 text-[#F8FAFC] text-sm">
                    <option value="domain">Domain</option>
                    <option value="cidr">CIDR</option>
                    <option value="ip">IP</option>
                  </select>
                </div>
                <div>
                  <label className="block text-xs text-[#94A3B8] mb-1">Wordlist</label>
                  <select value={form.wordlist} onChange={(e) => setForm({ ...form, wordlist: e.target.value })}
                    className="w-full bg-[#0B1220] border border-[#1E293B] rounded-md p-2 text-[#F8FAFC] text-sm">
                    <option value="passive">Passive Only</option>
                    <option value="small">+ Small</option>
                    <option value="medium">+ Medium</option>
                    <option value="large">+ Large</option>
                  </select>
                </div>
                <div>
                  <label className="block text-xs text-[#94A3B8] mb-1">Port Scan</label>
                  <select value={form.ports} onChange={(e) => setForm({ ...form, ports: e.target.value })}
                    className="w-full bg-[#0B1220] border border-[#1E293B] rounded-md p-2 text-[#F8FAFC] text-sm">
                    <option value="fast">Fast (Top 100)</option>
                    <option value="full">Full (Top 1000)</option>
                  </select>
                </div>
                <div>
                  <label className="block text-xs text-[#94A3B8] mb-1">Workers</label>
                  <Input type="number" value={form.workers} onChange={(e) => setForm({ ...form, workers: parseInt(e.target.value) || 50 })}
                    className="bg-[#0B1220] border-[#1E293B] text-[#F8FAFC] text-sm" />
                </div>
              </div>
              <Button onClick={handleCreate} disabled={scanning} size="sm" className="bg-[#3B82F6]">
                {scanning ? <Loader2 className="h-4 w-4 mr-1 animate-spin" /> : <Activity className="h-4 w-4 mr-1" />}
                {scanning ? "Starting..." : "Start Scan"}
              </Button>
            </CardContent>
          </Card>
        </div>
      )}

      {/* Scanning progress indicator */}
      {scanning && (
        <div className={colSpan(12)}>
          <Card className="border-[#1E293B] bg-[#1E293B]">
            <CardContent className="p-4">
              <div className="space-y-2">
                <div className="flex items-center justify-between text-sm">
                  <div className="flex items-center gap-2">
                    <Loader2 className="h-4 w-4 animate-spin text-[#3B82F6]" />
                    <span className="text-[#F8FAFC] font-medium">Scanning {form.target}...</span>
                  </div>
                </div>
                <div className="w-full bg-[#0B1220] rounded-full h-2 overflow-hidden">
                  <div className="h-full rounded-full animate-pulse bg-gradient-to-r from-[#3B82F6] to-[#8B5CF6]" style={{ width: "60%" }} />
                </div>
                <p className="text-xs text-[#94A3B8]">Running discovery, port scan, and CVE correlation. This may take a few minutes.</p>
              </div>
            </CardContent>
          </Card>
        </div>
      )}

      {loading ? <div className={colSpan(12)}><p className="text-[#94A3B8] text-sm">Loading...</p></div>
        : scans.length === 0 ? <div className={colSpan(12)}><Card className="border-[#1E293B] bg-[#1E293B]"><CardContent><EmptyState icon={Globe} title="No EASM scans yet" description="Run your first external attack surface scan to discover assets" /></CardContent></Card></div>
        : <div className={colSpan(12)}><div className="space-y-2">{scans.map((s) => (
            <Card key={s.id} className="border-[#1E293B] bg-[#1E293B] cursor-pointer hover:border-[#3B82F6]/50" onClick={() => navigate(`/easm/${s.id}`)}>
              <CardContent className="p-3">
                <div className="flex items-center justify-between gap-3">
                  <div className="flex items-center gap-3 min-w-0">
                    <div className={`p-1.5 rounded-lg shrink-0 ${s.status === "completed" ? "bg-green-500/10" : s.status === "failed" ? "bg-red-500/10" : "bg-blue-500/10"}`}>
                      <Globe className={`h-4 w-4 ${s.status === "completed" ? "text-green-400" : s.status === "failed" ? "text-red-400" : "text-blue-400"}`} />
                    </div>
                    <div className="min-w-0">
                      <h3 className="font-medium text-sm text-[#F8FAFC]">{s.target}</h3>
                      <p className="text-xs text-[#94A3B8]">{s.scan_type} · {s.wordlist} · {s.ports} ports</p>
                    </div>
                  </div>
                  <div className="flex items-center gap-3 shrink-0 text-xs">
                    <span className="text-[#94A3B8]">{s.alive_assets}/{s.total_assets} alive</span>
                    <span className="text-[#94A3B8]">{s.total_services} svc</span>
                    <span className="text-[#3B82F6] font-medium">{s.total_cves} CVEs</span>
                    <span className={`font-medium ${statusColor(s.status)}`}>{s.status}</span>
                  </div>
                </div>
              </CardContent>
            </Card>
          ))}</div></div>}
    </PageContainer>
  );
}
