import { Shield, Bug, AlertTriangle, Activity, Scan, RefreshCw } from "lucide-react";
import StatCard from "@/components/StatCard";
import { useDbInfo, useDbStats } from "@/hooks/useApi";
import { formatDate, severityBg } from "@/lib/utils";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";

export default function DashboardPage() {
  const { data: dbInfo, isLoading } = useDbInfo();
  const { data: stats } = useDbStats();

  const lastUpdate = dbInfo?.last_updated ? formatDate(dbInfo.last_updated) : "N/A";

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-bold text-[#F8FAFC]">Dashboard</h1>
        <p className="text-sm text-[#94A3B8] mt-1">
          Enterprise Infrastructure Vulnerability Scanner Overview
        </p>
      </div>

      {/* Summary Cards */}
      <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
        <StatCard
          title="Total CVEs"
          value={dbInfo?.cve_count.toLocaleString() ?? "—"}
          icon={Bug}
          color="#3B82F6"
          subtitle="In database"
          loading={isLoading}
        />
        <StatCard
          title="Critical"
          value="—"
          icon={AlertTriangle}
          color="#EF4444"
          subtitle="Above CVSS 9.0"
          loading={isLoading}
        />
        <StatCard
          title="KEV Entries"
          value={dbInfo?.kev_count.toLocaleString() ?? "—"}
          icon={Shield}
          color="#F59E0B"
          subtitle="Known Exploited Vulns"
          loading={isLoading}
        />
        <StatCard
          title="EPSS Scores"
          value={dbInfo?.epss_count.toLocaleString() ?? "—"}
          icon={Activity}
          color="#22C55E"
          subtitle="Exploit Prediction"
          loading={isLoading}
        />
      </div>

      <div className="grid gap-6 lg:grid-cols-2">
        {/* Database Info */}
        <Card className="border-[#1E293B] bg-[#1E293B]">
          <CardHeader>
            <CardTitle className="text-lg text-[#F8FAFC]">Database Status</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="space-y-3">
              <Row label="Schema Version" value={`v${dbInfo?.schema_version ?? "—"}`} />
              <Row label="Last Updated" value={lastUpdate} />
              <Row label="CVEs" value={(dbInfo?.cve_count ?? 0).toLocaleString()} />
              <Row label="CPEs" value={(dbInfo?.cpe_count ?? 0).toLocaleString()} />
              <Row label="KEV" value={(dbInfo?.kev_count ?? 0).toLocaleString()} />
              <Row label="EPSS" value={(dbInfo?.epss_count ?? 0).toLocaleString()} />
              <Row
                label="Integrity"
                value={
                  <Badge
                    variant="outline"
                    className={
                      dbInfo?.integrity_ok
                        ? "border-[#22C55E] text-[#22C55E]"
                        : "border-[#F59E0B] text-[#F59E0B]"
                    }
                  >
                    {dbInfo?.integrity_ok ? "Passed" : "Unknown"}
                  </Badge>
                }
              />
            </div>
          </CardContent>
        </Card>

        {/* Quick Actions */}
        <Card className="border-[#1E293B] bg-[#1E293B]">
          <CardHeader>
            <CardTitle className="text-lg text-[#F8FAFC]">Quick Actions</CardTitle>
          </CardHeader>
          <CardContent className="space-y-4">
            <ActionButton
              icon={Scan}
              label="New Host Scan"
              description="Scan a target for open ports and vulnerabilities"
              href="/host-discovery"
            />
            <ActionButton
              icon={RefreshCw}
              label="Update Feeds"
              description="Download latest CVE, KEV, and EPSS data"
              href="/updates"
            />
            <ActionButton
              icon={FileText}
              label="Generate Report"
              description="Export findings as HTML or JSON"
              href="/reports"
            />
          </CardContent>
        </Card>
      </div>

      {/* Recent Activity Placeholder */}
      <Card className="border-[#1E293B] bg-[#1E293B]">
        <CardHeader>
          <CardTitle className="text-lg text-[#F8FAFC]">Recent Scans</CardTitle>
        </CardHeader>
        <CardContent>
          <div className="flex items-center justify-center py-12 text-[#94A3B8]">
            <div className="text-center space-y-2">
              <Scan className="h-8 w-8 mx-auto opacity-50" />
              <p>No scans performed yet</p>
              <p className="text-sm">Run a host discovery scan to see results here</p>
            </div>
          </div>
        </CardContent>
      </Card>
    </div>
  );
}

function Row({ label, value }: { label: string; value: React.ReactNode }) {
  return (
    <div className="flex items-center justify-between border-b border-[#0B1220] pb-2 last:border-0">
      <span className="text-sm text-[#94A3B8]">{label}</span>
      <span className="text-sm font-medium text-[#F8FAFC]">{value}</span>
    </div>
  );
}

function ActionButton({
  icon: Icon,
  label,
  description,
  href,
}: {
  icon: React.ComponentType<{ className?: string }>;
  label: string;
  description: string;
  href: string;
}) {
  return (
    <a
      href={href}
      className="flex items-center gap-4 rounded-lg border border-[#0B1220] bg-[#0B1220] p-4 transition hover:border-[#3B82F6]/30"
    >
      <div className="rounded-lg bg-[#3B82F6]/10 p-2.5">
        <Icon className="h-5 w-5 text-[#3B82F6]" />
      </div>
      <div>
        <p className="text-sm font-medium text-[#F8FAFC]">{label}</p>
        <p className="text-xs text-[#94A3B8]">{description}</p>
      </div>
    </a>
  );
}

import { FileText } from "lucide-react";
