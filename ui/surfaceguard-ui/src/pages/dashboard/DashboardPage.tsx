import { useQuery } from "@tanstack/react-query";
import { useNavigate } from "react-router-dom";
import { Shield, Bug, AlertTriangle, Activity, Scan, RefreshCw } from "lucide-react";
import StatCard from "@/components/StatCard";
import { useDbInfo } from "@/hooks/useApi";
import { formatDate, severityColor } from "@/lib/utils";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import PageHeader from "@/components/PageHeader";
import PageContainer, { colSpan } from "@/components/PageContainer";
import EmptyState from "@/components/EmptyState";
import SeverityBadge from "@/components/SeverityBadge";
import axios from "axios";
import type { AssessmentResult } from "@/types";

export default function DashboardPage() {
  const navigate = useNavigate();
  const { data: dbInfo, isLoading } = useDbInfo();
  const { data: history } = useQuery<AssessmentResult[]>({
    queryKey: ["dashboard-scans"],
    queryFn: async () => {
      const { data } = await axios.get("/api/assessment/history", { params: { limit: 5 } });
      return data;
    },
    refetchInterval: 10000,
  });

  const lastUpdate = dbInfo?.last_updated ? formatDate(dbInfo.last_updated) : "N/A";
  const scans = history || [];

  return (
    <PageContainer>
      <div className={colSpan(12)}>
        <PageHeader title="Dashboard" description="Enterprise Infrastructure Vulnerability Scanner" />
      </div>

      {/* Summary Cards */}
      <div className={colSpan(3)}><StatCard title="Total CVEs" value={dbInfo?.cve_count?.toLocaleString() ?? "—"} icon={Bug} color="#3B82F6" subtitle="In database" loading={isLoading} /></div>
      <div className={colSpan(3)}><StatCard title="KEV Entries" value={dbInfo?.kev_count?.toLocaleString() ?? "—"} icon={AlertTriangle} color="#EF4444" subtitle="Known Exploited" loading={isLoading} /></div>
      <div className={colSpan(3)}><StatCard title="EPSS Scores" value={dbInfo?.epss_count?.toLocaleString() ?? "—"} icon={Activity} color="#22C55E" subtitle="Exploit Prediction" loading={isLoading} /></div>
      <div className={colSpan(3)}><StatCard title="Total Scans" value={scans.length.toString() || "0"} icon={Shield} color="#8B5CF6" subtitle="Completed assessments" /></div>

      {/* Recent Scans */}
      <div className={colSpan(8)}>
        <Card className="border-[#1E293B] bg-[#1E293B] h-full">
          <CardHeader className="pb-3">
            <CardTitle className="text-base text-[#F8FAFC]">Recent Scans</CardTitle>
          </CardHeader>
          <CardContent>
            {scans.length === 0 ? (
              <EmptyState icon={Scan} title="No scans yet" description="Run a CVE Discovery scan to see results here" />
            ) : (
              <div className="space-y-1">
                {scans.slice(0, 5).map((s) => (
                  <div key={s.id} className="flex items-center justify-between py-2 px-2 -mx-2 rounded hover:bg-[#0B1220]">
                    <div className="flex items-center gap-3 min-w-0">
                      <div className="h-2 w-2 rounded-full bg-[#22C55E] shrink-0" />
                      <span className="font-mono text-sm text-[#3B82F6] truncate">{s.target}</span>
                      <span className="text-xs text-[#64748B] whitespace-nowrap">{s.duration}</span>
                    </div>
                    <div className="flex items-center gap-3 shrink-0">
                      {s.cves && s.cves.length > 0 && (
                        <span className="text-xs text-[#F59E0B]">{s.cves.length} CVEs</span>
                      )}
                      {s.risk_score > 0 && (
                        <span className="text-xs font-mono font-bold" style={{ color: severityColor(s.risk_score > 70 ? "CRITICAL" : s.risk_score > 40 ? "HIGH" : "MEDIUM") }}>
                          {s.risk_score.toFixed(0)}
                        </span>
                      )}
                    </div>
                  </div>
                ))}
              </div>
            )}
          </CardContent>
        </Card>
      </div>

      {/* Quick Actions */}
      <div className={colSpan(4)}>
        <Card className="border-[#1E293B] bg-[#1E293B] h-full">
          <CardHeader className="pb-3">
            <CardTitle className="text-base text-[#F8FAFC]">Quick Actions</CardTitle>
          </CardHeader>
          <CardContent className="space-y-2">
            <ActionButton icon={Scan} label="New Scan" desc="Scan for open ports & CVEs" href="/cve-discovery" />
            <ActionButton icon={RefreshCw} label="Update Feeds" desc="Download latest CVE/KEV/EPSS" href="/updates" />
            <ActionButton icon={AlertTriangle} label="Assessment" desc="Run authenticated scan" href="/assessment" />
          </CardContent>
        </Card>
      </div>

      {/* Database Status */}
      <div className={colSpan(6)}>
        <Card className="border-[#1E293B] bg-[#1E293B] h-full">
          <CardHeader className="pb-3">
            <CardTitle className="text-base text-[#F8FAFC]">Database Status</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="grid grid-cols-2 gap-x-6 gap-y-1.5 text-sm">
              <Row label="Schema" value={`v${dbInfo?.schema_version ?? "—"}`} />
              <Row label="Last Updated" value={lastUpdate} />
              <Row label="CVEs" value={(dbInfo?.cve_count ?? 0).toLocaleString()} />
              <Row label="CPEs" value={(dbInfo?.cpe_count ?? 0).toLocaleString()} />
              <Row label="KEV" value={(dbInfo?.kev_count ?? 0).toLocaleString()} />
              <Row label="EPSS" value={(dbInfo?.epss_count ?? 0).toLocaleString()} />
              <Row label="Integrity" value={dbInfo?.integrity_ok ? "Passed" : "Unknown"} />
            </div>
          </CardContent>
        </Card>
      </div>

      {/* System Health */}
      <div className={colSpan(6)}>
        <Card className="border-[#1E293B] bg-[#1E293B] h-full">
          <CardHeader className="pb-3">
            <CardTitle className="text-base text-[#F8FAFC]">System Health</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="space-y-3">
              <HealthRow label="Database" status={dbInfo?.integrity_ok ? "Healthy" : "Unknown"} color={dbInfo?.integrity_ok ? "#22C55E" : "#F59E0B"} />
              <HealthRow label="Feeds" status={dbInfo?.cve_count ? "Up to date" : "Needs update"} color={dbInfo?.cve_count ? "#22C55E" : "#F59E0B"} />
              <HealthRow label="API Server" status="Healthy" color="#22C55E" />
            </div>
          </CardContent>
        </Card>
      </div>
    </PageContainer>
  );
}

function Row({ label, value }: { label: string; value: React.ReactNode }) {
  return (
    <div className="flex items-center justify-between py-1 border-b border-[#0B1220]/50 last:border-0">
      <span className="text-xs text-[#94A3B8]">{label}</span>
      <span className="text-xs font-medium text-[#F8FAFC]">{value}</span>
    </div>
  );
}

function ActionButton({ icon: Icon, label, desc, href }: { icon: React.ComponentType<{ className?: string }>; label: string; desc: string; href: string }) {
  const navigate = useNavigate();
  return (
    <div onClick={() => navigate(href)} className="flex items-center gap-3 rounded-lg border border-[#0B1220] bg-[#0B1220] p-3 transition hover:border-[#3B82F6]/30 cursor-pointer">
      <div className="rounded-lg bg-[#3B82F6]/10 p-2 shrink-0">
        <Icon className="h-4 w-4 text-[#3B82F6]" />
      </div>
      <div className="min-w-0">
        <p className="text-sm font-medium text-[#F8FAFC]">{label}</p>
        <p className="text-xs text-[#94A3B8] truncate">{desc}</p>
      </div>
    </div>
  );
}

function HealthRow({ label, status, color }: { label: string; status: string; color: string }) {
  return (
    <div className="flex items-center justify-between">
      <span className="text-sm text-[#94A3B8]">{label}</span>
      <div className="flex items-center gap-1.5">
        <div className="h-1.5 w-1.5 rounded-full" style={{ backgroundColor: color }} />
        <span className="text-sm font-medium text-[#F8FAFC]">{status}</span>
      </div>
    </div>
  );
}
