import { useState } from "react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { toast } from "sonner";
import { Monitor, Wifi, Play, Loader2, Download, Globe, Trash2 } from "lucide-react";
import PageHeader from "@/components/PageHeader";
import PageContainer, { colSpan } from "@/components/PageContainer";
import EmptyState from "@/components/EmptyState";

// Module-level ref that survives page navigation (component unmount/remount)
let persistentES: EventSource | null = null;

const SS_KEY = "hostdisc_state";

function loadHostState() {
  try { const r = sessionStorage.getItem(SS_KEY); return r ? JSON.parse(r) : null; } catch { return null; }
}

function saveHostState(s: Record<string, unknown>) {
  try { sessionStorage.setItem(SS_KEY, JSON.stringify(s)); } catch {}
}

export default function HostDiscoveryPage() {
  const saved = loadHostState();
  const [network, setNetwork] = useState("");
  const [scanning, setScanning] = useState(saved?.scanning || false);
  const [progress, setProgress] = useState(saved?.progress || 0);
  const [progressText, setProgressText] = useState(saved?.progressText || "");
  const [hosts, setHosts] = useState<string[]>(saved?.hosts || []);
  const [error, setError] = useState<string | null>(saved?.error || null);

  function upd(s: Record<string, unknown>) {
    if (s.scanning !== undefined) setScanning(s.scanning as boolean);
    if (s.progress !== undefined) setProgress(s.progress as number);
    if (s.progressText !== undefined) setProgressText(s.progressText as string);
    if (s.hosts !== undefined) setHosts(s.hosts as string[]);
    if (s.error !== undefined) setError(s.error as string | null);
    saveHostState({ scanning: s.scanning ?? scanning, progress: s.progress ?? progress, progressText: s.progressText ?? progressText, hosts: s.hosts ?? hosts, error: s.error ?? error });
  }

  const handleScan = () => {
    if (!network.trim()) return;
    upd({ scanning: true, progress: 0, progressText: "Starting host discovery...", hosts: [], error: null });

    const params = new URLSearchParams({ target: network.trim() });
    const es = new EventSource(`/api/host-discovery?${params}`);
    persistentES = es;

    es.onmessage = (event) => {
      try {
        const data = JSON.parse(event.data);
        if (data.type === "progress") { upd({ progress: data.percent, progressText: data.text }); }
        else if (data.type === "result") {
          upd({ hosts: data.hosts || [], progress: 100, progressText: `Found ${data.count} live host(s)`, scanning: false });
          es.close();
          toast.success(`Discovery complete — ${data.count} host(s) found`);
        } else if (data.type === "error") { upd({ error: data.message, scanning: false }); es.close(); toast.error(data.message); }
      } catch (_) {}
    };
    es.onerror = () => { upd({ error: "Connection lost", scanning: false }); es.close(); };
  };

  return (
    <PageContainer>
      <div className={colSpan(12)}>
        <PageHeader title="Host Discovery" description="Discover live hosts on a network via ping sweep" />
      </div>

      <div className={colSpan(12)}>
        <Card className="border-[#1E293B] bg-[#1E293B]">
          <CardContent className="p-3.5 space-y-3">
            <div className="flex gap-2">
              <div className="flex-1">
                <Input placeholder="Network (e.g., 192.168.1.0/24) or IP" value={network} onChange={(e) => setNetwork(e.target.value)} onKeyDown={(e) => e.key === "Enter" && handleScan()} className="border-[#0B1220] bg-[#0B1220] text-[#F8FAFC] placeholder:text-[#94A3B8] font-mono text-sm" />
              </div>
              <Button onClick={handleScan} disabled={scanning || !network.trim()} className="bg-[#3B82F6] hover:bg-[#2563EB] shrink-0">
                {scanning ? <Loader2 className="h-4 w-4 mr-2 animate-spin" /> : <Wifi className="h-4 w-4 mr-2" />}
                {scanning ? "Scanning..." : "Discover"}
              </Button>
            </div>
            {scanning && (
              <div className="space-y-1">
                <div className="flex items-center justify-between text-xs">
                  <span className="text-[#94A3B8]">{progressText}</span>
                  <span className="text-[#3B82F6] font-mono font-bold">{progress}%</span>
                </div>
                <div className="h-2 rounded-full bg-[#0B1220] overflow-hidden">
                  <div className="h-full rounded-full bg-gradient-to-r from-[#3B82F6] to-[#22C55E] transition-all duration-500" style={{ width: `${progress}%` }} />
                </div>
              </div>
            )}
          </CardContent>
        </Card>
      </div>

      {error && <div className={colSpan(12)}><Card className="border-[#EF4444]/30 bg-[#1E293B]"><CardContent className="p-3.5"><p className="text-xs text-[#EF4444]">{error}</p></CardContent></Card></div>}

      {hosts.length > 0 && (
        <div className={colSpan(12)}>
          <Card className="border-[#1E293B] bg-[#1E293B]">
            <CardHeader className="flex flex-row items-center justify-between pb-3">
              <CardTitle className="text-base text-[#F8FAFC]">Live Hosts ({hosts.length})</CardTitle>
              <div className="flex gap-2">
              <Button variant="outline" size="sm" className="border-red-500/30 text-red-400 hover:bg-red-500/10 h-8"
                onClick={() => { upd({ hosts: [], progress: 0, progressText: "" }); }}>
                <Trash2 className="h-3 w-3 mr-1" /> Clear
              </Button>
              <Button variant="outline" size="sm" className="border-[#0B1220] text-[#94A3B8] h-8"
                onClick={() => {
                  const text = hosts.join("\n");
                  const blob = new Blob([text], { type: "text/plain" });
                  const url = URL.createObjectURL(blob);
                  const a = document.createElement("a");
                  a.href = url;
                  a.download = `hosts-${network.trim().replace("/", "_")}.txt`;
                  a.click();
                  setTimeout(() => URL.revokeObjectURL(url), 1000);
                  toast.success("Exported");
                }}>
                <Download className="h-3 w-3 mr-1" /> Export
              </Button>
              </div>
            </CardHeader>
            <CardContent>
              <div className="grid gap-2 grid-cols-2 sm:grid-cols-3 md:grid-cols-4 lg:grid-cols-6 xl:grid-cols-8">
                {hosts.map((ip) => (
                  <div key={ip} className="flex items-center gap-2 rounded-lg border border-[#0B1220] bg-[#0B1220] p-2.5">
                    <div className="h-1.5 w-1.5 rounded-full bg-[#22C55E]" />
                    <Globe className="h-3 w-3 text-[#3B82F6] shrink-0" />
                    <span className="font-mono text-xs text-[#F8FAFC] truncate">{ip}</span>
                  </div>
                ))}
              </div>
            </CardContent>
          </Card>
        </div>
      )}

      {!scanning && hosts.length === 0 && !error && (
        <div className={colSpan(12)}>
          <Card className="border-[#1E293B] bg-[#1E293B]">
            <CardContent><EmptyState icon={Monitor} title="Enter a network to discover live hosts" description="Supports CIDR notation (e.g., 192.168.1.0/24) or single IP" /></CardContent>
          </Card>
        </div>
      )}
    </PageContainer>
  );
}
