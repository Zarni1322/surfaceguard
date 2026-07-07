import { useState, useRef, useEffect } from "react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { toast } from "sonner";
import { Monitor, Wifi, Play, Loader2, Download, Globe } from "lucide-react";

interface HostResult {
  hosts: string[];
  count: number;
}

export default function HostDiscoveryPage() {
  const [network, setNetwork] = useState("");
  const [scanning, setScanning] = useState(false);
  const [progress, setProgress] = useState(0);
  const [progressText, setProgressText] = useState("");
  const [hosts, setHosts] = useState<string[]>([]);
  const [error, setError] = useState<string | null>(null);
  const eventSourceRef = useRef<EventSource | null>(null);

  const handleScan = () => {
    if (!network.trim()) return;
    setScanning(true);
    setProgress(0);
    setProgressText("Starting host discovery...");
    setHosts([]);
    setError(null);

    const params = new URLSearchParams({ target: network.trim() });
    const es = new EventSource(`/api/host-discovery?${params}`);
    eventSourceRef.current = es;

    es.onmessage = (event) => {
      try {
        const data = JSON.parse(event.data);
        if (data.type === "progress") {
          setProgress(data.percent);
          setProgressText(data.text);
        } else if (data.type === "result") {
          setHosts(data.hosts || []);
          setProgress(100);
          setProgressText(`Found ${data.count} live host(s)`);
          setScanning(false);
          es.close();
          toast.success(`Discovery complete — ${data.count} host(s) found`);
        } else if (data.type === "error") {
          setError(data.message);
          setScanning(false);
          es.close();
          toast.error(data.message);
        }
      } catch (e) {
        // ignore parse errors
      }
    };

    es.onerror = () => {
      setError("Connection lost");
      setScanning(false);
      es.close();
    };
  };

  useEffect(() => {
    return () => {
      if (eventSourceRef.current) eventSourceRef.current.close();
    };
  }, []);

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-bold text-[#F8FAFC]">Host Discovery</h1>
        <p className="text-sm text-[#94A3B8] mt-1">Discover live hosts on a network via ping sweep</p>
      </div>

      <Card className="border-[#1E293B] bg-[#1E293B]">
        <CardContent className="pt-6 space-y-4">
          <div className="flex gap-3">
            <div className="flex-1">
              <Input
                placeholder="Network (e.g., 192.168.1.0/24) or single IP"
                value={network}
                onChange={(e) => setNetwork(e.target.value)}
                onKeyDown={(e) => e.key === "Enter" && handleScan()}
                className="border-[#0B1220] bg-[#0B1220] text-[#F8FAFC] placeholder:text-[#94A3B8] font-mono"
              />
            </div>
            <Button
              onClick={handleScan}
              disabled={scanning || !network.trim()}
              className="bg-[#3B82F6] hover:bg-[#2563EB] text-white min-w-[140px]"
            >
              {scanning ? (
                <Loader2 className="h-4 w-4 mr-2 animate-spin" />
              ) : (
                <Wifi className="h-4 w-4 mr-2" />
              )}
              {scanning ? "Scanning..." : "Discover Hosts"}
            </Button>
          </div>

          {scanning && (
            <div className="space-y-2">
              <div className="flex items-center justify-between text-sm">
                <span className="text-[#94A3B8]">{progressText}</span>
                <span className="text-[#3B82F6] font-mono font-bold">{progress}%</span>
              </div>
              <div className="h-2.5 rounded-full bg-[#0B1220] overflow-hidden">
                <div
                  className="h-full rounded-full bg-gradient-to-r from-[#3B82F6] to-[#22C55E] transition-all duration-500 ease-out"
                  style={{ width: `${progress}%` }}
                />
              </div>
            </div>
          )}
        </CardContent>
      </Card>

      {error && (
        <Card className="border-[#EF4444]/30 bg-[#1E293B]">
          <CardContent className="pt-6">
            <p className="text-[#EF4444]">{error}</p>
          </CardContent>
        </Card>
      )}

      {/* Results */}
      {hosts.length > 0 && (
        <Card className="border-[#1E293B] bg-[#1E293B]">
          <CardHeader className="flex flex-row items-center justify-between">
            <CardTitle className="text-lg text-[#F8FAFC]">
              Live Hosts ({hosts.length})
            </CardTitle>
            <Button
              variant="outline"
              size="sm"
              className="border-[#0B1220] text-[#94A3B8]"
              onClick={() => {
                const text = hosts.join("\n");
                const blob = new Blob([text], { type: "text/plain" });
                const a = document.createElement("a");
                a.href = URL.createObjectURL(blob);
                a.download = `hosts-${network.trim().replace("/", "_")}.txt`;
                a.click();
                toast.success("Host list exported");
              }}
            >
              <Download className="h-4 w-4 mr-2" /> Export
            </Button>
          </CardHeader>
          <CardContent>
            <div className="grid gap-2 sm:grid-cols-2 md:grid-cols-3 lg:grid-cols-4">
              {hosts.map((ip) => (
                <div
                  key={ip}
                  className="flex items-center gap-3 rounded-lg border border-[#0B1220] bg-[#0B1220] p-3"
                >
                  <div className="h-2 w-2 rounded-full bg-[#22C55E] animate-pulse" />
                  <Globe className="h-4 w-4 text-[#3B82F6]" />
                  <span className="font-mono text-sm text-[#F8FAFC]">{ip}</span>
                </div>
              ))}
            </div>
          </CardContent>
        </Card>
      )}

      {!scanning && hosts.length === 0 && !error && (
        <Card className="border-[#1E293B] bg-[#1E293B]">
          <CardContent className="flex items-center justify-center py-20 text-[#94A3B8]">
            <div className="text-center space-y-3">
              <Monitor className="h-12 w-12 mx-auto opacity-20" />
              <p className="text-lg">Enter a network to discover live hosts</p>
              <p className="text-sm">Supports CIDR notation (e.g., 192.168.1.0/24) or single IP</p>
            </div>
          </CardContent>
        </Card>
      )}
    </div>
  );
}
