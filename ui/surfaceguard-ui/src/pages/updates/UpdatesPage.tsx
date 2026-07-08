import { useState, useEffect } from "react";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { toast } from "sonner";
import { RefreshCw, Loader2, Database, CheckCircle2, AlertCircle, Globe, Download, Shield, Trash2 } from "lucide-react";
import { useDbInfo } from "@/hooks/useApi";
import { getWordlistStatus, downloadWordlists, verifyWordlists, deleteWordlists, checkWordlistUpdates } from "@/api/client";
import { formatDate } from "@/lib/utils";
import PageContainer, { colSpan } from "@/components/PageContainer";
import PageHeader from "@/components/PageHeader";

// Module-level ref that survives page navigation
let persistentES: EventSource | null = null;

const SS_KEY = "update_state";

function loadUpdState() {
  try { const r = sessionStorage.getItem(SS_KEY); return r ? JSON.parse(r) : null; } catch { return null; }
}

function saveUpdState(s: Record<string, unknown>) {
  try { sessionStorage.setItem(SS_KEY, JSON.stringify(s)); } catch {}
}

export default function UpdatesPage() {
  const saved = loadUpdState();
  const { data: dbInfo, isLoading, refetch } = useDbInfo();
  const [updating, setUpdating] = useState(saved?.updating || false);
  const [progress, setProgress] = useState(saved?.progress || 0);
  const [progressText, setProgressText] = useState(saved?.progressText || "");
  const [phase, setPhase] = useState(saved?.phase || "idle");

  function upd(s: Record<string, unknown>) {
    if (s.updating !== undefined) setUpdating(s.updating as boolean);
    if (s.progress !== undefined) setProgress(s.progress as number);
    if (s.progressText !== undefined) setProgressText(s.progressText as string);
    if (s.phase !== undefined) setPhase(s.phase as string);
    saveUpdState({ updating: s.updating ?? updating, progress: s.progress ?? progress, progressText: s.progressText ?? progressText, phase: s.phase ?? phase });
  }

  const handleUpdate = () => {
    upd({ updating: true, progress: 0, progressText: "Starting update...", phase: "downloading" });

    const es = new EventSource("/api/update");
    persistentES = es;

    es.onmessage = (event) => {
      try {
        const data = JSON.parse(event.data);
        if (data.type === "progress") { upd({ progress: data.percent, progressText: data.text }); }
        else if (data.type === "result" && data.status === "completed") {
          upd({ progress: 100, progressText: "Update complete", phase: "complete", updating: false });
          es.close(); refetch(); toast.success("All feeds updated");
        }
      } catch { /* ignore */ }
    };

    es.onerror = () => {
      if (progress >= 100) return;
      upd({ progressText: "Connection lost — update may still be running", updating: false });
      es.close();
    };
  };

  const [wlStatus, setWlStatus] = useState<any>(null);
  const [wlLoading, setWlLoading] = useState(false);
  const [wlDownloading, setWlDownloading] = useState(false);

  useEffect(() => { loadWlStatus(); }, []);

  async function loadWlStatus() {
    try { setWlStatus(await getWordlistStatus()); } catch {}
  }

  async function handleWlDownload() {
    setWlDownloading(true);
    try {
      await downloadWordlists();
      toast.success("Wordlists downloaded");
      loadWlStatus();
    } catch { toast.error("Download failed"); } finally { setWlDownloading(false); }
  }

  async function handleWlVerify() {
    try {
      const r = await verifyWordlists();
      toast.success(r.valid ? "All wordlists valid" : "Corruption detected");
    } catch { toast.error("Verify failed"); }
  }

  async function handleWlDelete() {
    if (!window.confirm("Delete all cached wordlists?")) return;
    try { await deleteWordlists(); toast.success("Wordlists deleted"); loadWlStatus(); } catch { toast.error("Delete failed"); }
  }

  async function handleWlCheckUpdate() {
    try {
      const r = await checkWordlistUpdates();
      if (r.needs_update) toast.info("Update available: " + r.latest_version);
      else toast.success("Already up to date");
      loadWlStatus();
    } catch { toast.error("Check failed"); }
  }

  const lastUpdate = dbInfo?.last_updated ? formatDate(dbInfo.last_updated) : "Unknown";
  const feedStatus = updating ? "updating" : (dbInfo?.cve_count ? "up-to-date" : "unknown");

  return (
    <PageContainer>
      <div className={colSpan(12)}>
      <PageHeader title="Update Center" description="Manage vulnerability feed updates"
        actions={<Button
          onClick={handleUpdate}
          disabled={updating}
          className="bg-[#3B82F6] hover:bg-[#2563EB] text-white min-w-[160px]"
        >
          {updating ? (
            <Loader2 className="h-4 w-4 mr-2 animate-spin" />
          ) : (
            <RefreshCw className="h-4 w-4 mr-2" />
          )}
          {updating ? "Updating..." : "Update Security Feeds"}
        </Button>} />
      </div>

      <div className={colSpan(12)}>
      {/* Real-time Progress Bar */}
      {updating && (
        <Card className="border-[#1E293B] bg-[#1E293B]">
          <CardContent className="pt-6 space-y-4">
            <div className="flex items-center justify-between text-sm">
              <span className="text-[#94A3B8]">{progressText}</span>
              <span className="text-[#3B82F6] font-mono font-bold">{progress}%</span>
            </div>
            <div className="h-3 rounded-full bg-[#0B1220] overflow-hidden">
              <div
                className="h-full rounded-full bg-gradient-to-r from-[#3B82F6] via-[#8B5CF6] to-[#22C55E] transition-all duration-500 ease-out"
                style={{ width: `${progress}%` }}
              />
            </div>
            <div className="flex items-center gap-2 text-xs text-[#94A3B8]">
              <div className="h-2 w-2 rounded-full bg-[#3B82F6] animate-pulse" />
              Downloading security feed data — this may take several minutes
            </div>
          </CardContent>
        </Card>
      )}

      {/* Feed Cards */}
      <div className="grid gap-3 grid-cols-1 sm:grid-cols-2 lg:grid-cols-3">
        <FeedCard
          name="NVD"
          description="National Vulnerability Database"
          count={dbInfo?.cve_count ?? 0}
          lastUpdate={lastUpdate}
          loading={isLoading || (updating && phase === "downloading")}
          status={feedStatus}
        />
        <FeedCard
          name="CISA KEV"
          description="Known Exploited Vulnerabilities"
          count={dbInfo?.kev_count ?? 0}
          lastUpdate={lastUpdate}
          loading={isLoading}
          status={dbInfo?.kev_count ? "up-to-date" : "unknown"}
        />
        <FeedCard
          name="FIRST EPSS"
          description="Exploit Prediction Scoring"
          count={dbInfo?.epss_count ?? 0}
          lastUpdate={lastUpdate}
          loading={isLoading}
          status={dbInfo?.epss_count ? "up-to-date" : "unknown"}
        />
      </div>

      {/* Wordlists Section */}
      <Card className="border-[#1E293B] bg-[#1E293B]">
        <CardHeader className="flex flex-row items-center justify-between">
          <CardTitle className="text-lg text-[#F8FAFC] flex items-center gap-2">
            <Globe className="h-5 w-5 text-[#3B82F6]" /> DNS Wordlists
          </CardTitle>
        </CardHeader>
        <CardContent>
          {wlStatus ? (
            <div className="space-y-4">
              <div className="grid gap-3 grid-cols-2 sm:grid-cols-4">
                <div className="rounded-lg bg-[#0B1220] p-4">
                  <p className="text-xs text-[#94A3B8]">Status</p>
                  <p className={`text-sm font-bold mt-1 ${wlStatus.installed ? (wlStatus.needs_update ? "text-[#F59E0B]" : "text-[#22C55E]") : "text-[#F59E0B]"}`}>
                    {wlStatus.installed ? (wlStatus.needs_update ? "Update Available" : "Installed") : "Not Installed"}
                  </p>
                </div>
                <div className="rounded-lg bg-[#0B1220] p-4">
                  <p className="text-xs text-[#94A3B8]">Installed Version</p>
                  <p className="text-lg font-bold text-[#F8FAFC]">{wlStatus.current_version || "—"}</p>
                </div>
                <div className="rounded-lg bg-[#0B1220] p-4">
                  <p className="text-xs text-[#94A3B8]">Latest Version</p>
                  <p className="text-lg font-bold text-[#3B82F6]">{wlStatus.latest_version || "—"}</p>
                </div>
                <div className="rounded-lg bg-[#0B1220] p-4">
                  <p className="text-xs text-[#94A3B8]">Last Updated</p>
                  <p className="text-sm font-bold text-[#F8FAFC]">{wlStatus.last_updated ? new Date(wlStatus.last_updated).toLocaleDateString() : "—"}</p>
                </div>
              </div>
              {wlStatus.counts && (
                <div className="grid gap-3 grid-cols-3">
                  <div className="rounded-lg bg-[#0B1220] p-3 flex items-center justify-between">
                    <span className="text-xs text-[#94A3B8]">Small</span>
                    <span className="text-sm font-bold text-[#F8FAFC]">{(wlStatus.counts.small || 0).toLocaleString()} names</span>
                  </div>
                  <div className="rounded-lg bg-[#0B1220] p-3 flex items-center justify-between">
                    <span className="text-xs text-[#94A3B8]">Medium</span>
                    <span className="text-sm font-bold text-[#F8FAFC]">{(wlStatus.counts.medium || 0).toLocaleString()} names</span>
                  </div>
                  <div className="rounded-lg bg-[#0B1220] p-3 flex items-center justify-between">
                    <span className="text-xs text-[#94A3B8]">Large</span>
                    <span className="text-sm font-bold text-[#F8FAFC]">{(wlStatus.counts.large || 0).toLocaleString()} names</span>
                  </div>
                </div>
              )}
              <div className="flex flex-wrap gap-2">
                <Button variant="outline" size="sm" className="border-[#0B1220] text-[#94A3B8] h-8" onClick={handleWlCheckUpdate} disabled={wlLoading}><RefreshCw className="h-3 w-3 mr-1" />Check Updates</Button>
                {wlStatus.installed ? (
                  <Button onClick={handleWlDownload} disabled={wlDownloading} size="sm" className="bg-[#3B82F6] hover:bg-[#2563EB] h-8">
                    {wlDownloading ? <Loader2 className="h-4 w-4 mr-1 animate-spin" /> : <Download className="h-4 w-4 mr-1" />}
                    {wlDownloading ? "Updating..." : "Update"}
                  </Button>
                ) : (
                  <Button onClick={handleWlDownload} disabled={wlDownloading} size="sm" className="bg-[#3B82F6] hover:bg-[#2563EB] h-8">
                    {wlDownloading ? <Loader2 className="h-4 w-4 mr-1 animate-spin" /> : <Download className="h-4 w-4 mr-1" />}
                    {wlDownloading ? "Downloading..." : "Download"}
                  </Button>
                )}
                <Button variant="outline" size="sm" className="border-[#0B1220] text-[#94A3B8] h-8" onClick={handleWlVerify} disabled={wlLoading}><Shield className="h-3 w-3 mr-1" />Verify</Button>
                <Button variant="outline" size="sm" className="border-red-500/30 text-red-400 hover:bg-red-500/10 h-8" onClick={handleWlDelete} disabled={wlLoading}><Trash2 className="h-3 w-3 mr-1" />Delete Cache</Button>
              </div>
              {wlStatus.installed && !wlStatus.needs_update && (
                <p className="text-xs text-[#22C55E] flex items-center gap-1"><CheckCircle2 className="h-3 w-3" /> Already up-to-date</p>
              )}
              {wlStatus.installed && wlStatus.needs_update && (
                <p className="text-xs text-[#F59E0B] flex items-center gap-1"><AlertCircle className="h-3 w-3" /> Update available — latest: {wlStatus.latest_version}</p>
              )}
            </div>
          ) : (
            <div className="flex items-center justify-center py-8">
              <Loader2 className="h-5 w-5 animate-spin text-[#3B82F6] mr-2" />
              <span className="text-sm text-[#94A3B8]">Loading wordlist status...</span>
            </div>
          )}
        </CardContent>
      </Card>

      {/* Database Summary — moved after feeds, before wordlists */}
      <Card className="border-[#1E293B] bg-[#1E293B]">
        <CardHeader>
          <CardTitle className="text-lg text-[#F8FAFC]">Database Summary</CardTitle>
        </CardHeader>
        <CardContent>
          <div className="grid gap-3 grid-cols-2 sm:grid-cols-3 lg:grid-cols-4">
            <div className="rounded-lg bg-[#0B1220] p-4">
              <p className="text-xs text-[#94A3B8]">Schema</p>
              <p className="text-lg font-bold text-[#F8FAFC]">v{dbInfo?.schema_version ?? "—"}</p>
            </div>
            <div className="rounded-lg bg-[#0B1220] p-4">
              <p className="text-xs text-[#94A3B8]">CVEs</p>
              <p className="text-lg font-bold text-[#3B82F6]">{(dbInfo?.cve_count ?? 0).toLocaleString()}</p>
            </div>
            <div className="rounded-lg bg-[#0B1220] p-4">
              <p className="text-xs text-[#94A3B8]">CPEs</p>
              <p className="text-lg font-bold text-[#8B5CF6]">{(dbInfo?.cpe_count ?? 0).toLocaleString()}</p>
            </div>
            <div className="rounded-lg bg-[#0B1220] p-4">
              <p className="text-xs text-[#94A3B8]">KEV</p>
              <p className="text-lg font-bold text-[#F59E0B]">{(dbInfo?.kev_count ?? 0).toLocaleString()}</p>
            </div>
            <div className="rounded-lg bg-[#0B1220] p-4">
              <p className="text-xs text-[#94A3B8]">EPSS</p>
              <p className="text-lg font-bold text-[#22C55E]">{(dbInfo?.epss_count ?? 0).toLocaleString()}</p>
            </div>
            <div className="rounded-lg bg-[#0B1220] p-4">
              <p className="text-xs text-[#94A3B8]">Integrity</p>
              <p className="text-lg font-bold text-[#F8FAFC]">{dbInfo?.integrity_ok ? "Verified" : "Unknown"}</p>
            </div>
            <div className="rounded-lg bg-[#0B1220] p-4 sm:col-span-2 lg:col-span-1">
              <p className="text-xs text-[#94A3B8]">Last Updated</p>
              <p className="text-sm font-bold text-[#F8FAFC]">{lastUpdate}</p>
            </div>
          </div>
        </CardContent>
      </Card>
      </div>
    </PageContainer>
  );
}

function FeedCard({
  name,
  description,
  count,
  lastUpdate,
  loading,
  status,
}: {
  name: string;
  description: string;
  count: number;
  lastUpdate: string;
  loading: boolean;
  status: string;
}) {
  return (
    <Card className="border-[#1E293B] bg-[#1E293B] transition hover:border-[#3B82F6]/30">
      <CardContent className="pt-6">
        <div className="flex items-start gap-4">
          <div className="rounded-lg bg-[#3B82F6]/10 p-3">
            <Database className="h-5 w-5 text-[#3B82F6]" />
          </div>
          <div className="flex-1">
            <div className="flex items-center gap-2">
              <h3 className="font-semibold text-[#F8FAFC]">{name}</h3>
              {status === "up-to-date" ? (
                <CheckCircle2 className="h-4 w-4 text-[#22C55E]" />
              ) : status === "updating" ? (
                <Loader2 className="h-4 w-4 animate-spin text-[#3B82F6]" />
              ) : (
                <AlertCircle className="h-4 w-4 text-[#F59E0B]" />
              )}
            </div>
            <p className="text-xs text-[#94A3B8] mt-1">{description}</p>
            <div className="mt-4 space-y-1.5">
              <div className="flex justify-between text-sm">
                <span className="text-[#94A3B8]">Records</span>
                <span className="font-medium text-[#F8FAFC]">
                  {loading ? "..." : count.toLocaleString()}
                </span>
              </div>
              <div className="flex justify-between text-sm">
                <span className="text-[#94A3B8]">Updated</span>
                <span className="text-[#F8FAFC]">{loading ? "..." : lastUpdate}</span>
              </div>
              <div className="flex justify-between text-sm">
                <span className="text-[#94A3B8]">Status</span>
                <Badge
                  variant="outline"
                  className={
                    status === "up-to-date"
                      ? "border-[#22C55E] text-[#22C55E] text-[10px]"
                      : status === "updating"
                      ? "border-[#3B82F6] text-[#3B82F6] text-[10px] animate-pulse"
                      : "border-[#F59E0B] text-[#F59E0B] text-[10px]"
                  }
                >
                  {status === "up-to-date" ? "Up-to-date" : status === "updating" ? "Updating..." : "Unknown"}
                </Badge>
              </div>
            </div>
          </div>
        </div>
      </CardContent>
    </Card>
  );
}
