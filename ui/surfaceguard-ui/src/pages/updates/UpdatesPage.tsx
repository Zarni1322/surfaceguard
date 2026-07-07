import { useState } from "react";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { toast } from "sonner";
import { RefreshCw, Loader2, Database, CheckCircle2, AlertCircle } from "lucide-react";
import { useDbInfo, useTriggerUpdate } from "@/hooks/useApi";
import { formatDate } from "@/lib/utils";

export default function UpdatesPage() {
  const { data: dbInfo, isLoading, refetch } = useDbInfo();
  const updateMutation = useTriggerUpdate();
  const [progress, setProgress] = useState(0);
  const [progressText, setProgressText] = useState("");
  const [updating, setUpdating] = useState(false);

  const handleUpdate = () => {
    setUpdating(true);
    setProgress(0);
    setProgressText("Starting update...");

    const interval = setInterval(() => {
      setProgress(prev => {
        if (prev >= 85) return prev;
        return prev + Math.random() * 5;
      });
    }, 1000);

    updateMutation.mutate(undefined, {
      onSuccess: () => {
        clearInterval(interval);
        setProgress(100);
        setProgressText("Update complete");
        setTimeout(() => {
          setUpdating(false);
          refetch();
        }, 1000);
        toast.success("All feeds updated successfully");
      },
      onError: (err: any) => {
        clearInterval(interval);
        setProgress(0);
        setUpdating(false);
        toast.error(err?.message || "Update failed");
      },
    });
  };

  const lastUpdate = dbInfo?.last_updated ? formatDate(dbInfo.last_updated) : "Unknown";

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-[#F8FAFC]">Update Center</h1>
          <p className="text-sm text-[#94A3B8] mt-1">Manage vulnerability feed updates</p>
        </div>
        <Button
          onClick={handleUpdate}
          disabled={updating}
          className="bg-[#3B82F6] hover:bg-[#2563EB] text-white min-w-[160px]"
        >
          {updating ? (
            <Loader2 className="h-4 w-4 mr-2 animate-spin" />
          ) : (
            <RefreshCw className="h-4 w-4 mr-2" />
          )}
          {updating ? "Updating..." : "Update All Feeds"}
        </Button>
      </div>

      {/* Progress Bar */}
      {updating && (
        <Card className="border-[#1E293B] bg-[#1E293B]">
          <CardContent className="pt-6 space-y-3">
            <div className="flex items-center justify-between text-sm">
              <span className="text-[#94A3B8]">{progressText}</span>
              <span className="text-[#3B82F6] font-mono font-bold">{Math.round(progress)}%</span>
            </div>
            <div className="h-3 rounded-full bg-[#0B1220] overflow-hidden">
              <div
                className="h-full rounded-full bg-gradient-to-r from-[#3B82F6] to-[#22C55E] transition-all duration-700 ease-out"
                style={{ width: `${Math.min(progress, 100)}%` }}
              />
            </div>
            <p className="text-xs text-[#94A3B8]">
              Downloading and processing CVE, KEV, and EPSS data...
            </p>
          </CardContent>
        </Card>
      )}

      {/* Feed Cards */}
      <div className="grid gap-4 md:grid-cols-3">
        <FeedCard
          name="NVD"
          description="National Vulnerability Database"
          count={dbInfo?.cve_count ?? 0}
          lastUpdate={lastUpdate}
          loading={isLoading}
          status={dbInfo?.cve_count ? "up-to-date" : "unknown"}
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

      {/* DB Info */}
      <Card className="border-[#1E293B] bg-[#1E293B]">
        <CardHeader>
          <CardTitle className="text-lg text-[#F8FAFC]">Database Summary</CardTitle>
        </CardHeader>
        <CardContent>
          <div className="grid gap-4 md:grid-cols-4">
            <div className="rounded-lg bg-[#0B1220] p-4">
              <p className="text-xs text-[#94A3B8]">Schema</p>
              <p className="text-lg font-bold text-[#F8FAFC]">v{dbInfo?.schema_version ?? "—"}</p>
            </div>
            <div className="rounded-lg bg-[#0B1220] p-4">
              <p className="text-xs text-[#94A3B8]">CVEs</p>
              <p className="text-lg font-bold text-[#3B82F6]">{(dbInfo?.cve_count ?? 0).toLocaleString()}</p>
            </div>
            <div className="rounded-lg bg-[#0B1220] p-4">
              <p className="text-xs text-[#94A3B8]">KEV</p>
              <p className="text-lg font-bold text-[#F59E0B]">{(dbInfo?.kev_count ?? 0).toLocaleString()}</p>
            </div>
            <div className="rounded-lg bg-[#0B1220] p-4">
              <p className="text-xs text-[#94A3B8]">EPSS</p>
              <p className="text-lg font-bold text-[#22C55E]">{(dbInfo?.epss_count ?? 0).toLocaleString()}</p>
            </div>
          </div>
        </CardContent>
      </Card>
    </div>
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
                      : "border-[#F59E0B] text-[#F59E0B] text-[10px]"
                  }
                >
                  {status === "up-to-date" ? "Up-to-date" : "Unknown"}
                </Badge>
              </div>
            </div>
          </div>
        </div>
      </CardContent>
    </Card>
  );
}
