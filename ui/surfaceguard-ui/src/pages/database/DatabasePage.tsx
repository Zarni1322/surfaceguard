import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { useDbInfo } from "@/hooks/useApi";
import { formatDate } from "@/lib/utils";
import { Database, RefreshCw, Shield, Trash2 } from "lucide-react";
import PageContainer from "@/components/PageContainer";
import PageHeader from "@/components/PageHeader";

export default function DatabasePage() {
  const { data: dbInfo, isLoading } = useDbInfo();

  const lastUpdate = dbInfo?.last_updated ? formatDate(dbInfo.last_updated) : "N/A";

  return (
    <PageContainer>
      <PageHeader title="Database" description="Vulnerability database management" />

      <div className="grid gap-3 grid-cols-1 lg:grid-cols-2">
        <Card className="border-[#1E293B] bg-[#1E293B]">
          <CardHeader>
            <CardTitle className="text-lg text-[#F8FAFC]">Database Statistics</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="space-y-3">
              <StatRow label="Schema Version" value={`v${dbInfo?.schema_version ?? "—"}`} />
              <StatRow label="Last Updated" value={lastUpdate} />
              <StatRow label="Total CVEs" value={(dbInfo?.cve_count ?? 0).toLocaleString()} />
              <StatRow label="Total CPEs" value={(dbInfo?.cpe_count ?? 0).toLocaleString()} />
              <StatRow label="Products" value={(dbInfo?.product_count ?? 0).toLocaleString()} />
              <StatRow label="Vendors" value={(dbInfo?.vendor_count ?? 0).toLocaleString()} />
              <StatRow label="KEV Entries" value={(dbInfo?.kev_count ?? 0).toLocaleString()} />
              <StatRow label="EPSS Entries" value={(dbInfo?.epss_count ?? 0).toLocaleString()} />
              <StatRow
                label="Integrity Check"
                value={
                  <Badge
                    variant="outline"
                    className={
                      dbInfo?.integrity_ok
                        ? "border-[#22C55E] text-[#22C55E]"
                        : "border-[#F59E0B] text-[#F59E0B]"
                    }
                  >
                    {dbInfo?.integrity_ok ? "Passed" : "Not Run"}
                  </Badge>
                }
              />
            </div>
          </CardContent>
        </Card>

        <Card className="border-[#1E293B] bg-[#1E293B]">
          <CardHeader>
            <CardTitle className="text-lg text-[#F8FAFC]">Actions</CardTitle>
          </CardHeader>
          <CardContent className="space-y-3">
            <ActionItem icon={RefreshCw} label="Verify Integrity" desc="Run PRAGMA integrity_check" />
            <ActionItem icon={Database} label="Vacuum Database" desc="Reclaim unused space" />
            <ActionItem icon={Shield} label="Update Feeds" desc="Download latest CVE/KEV/EPSS" />
            <ActionItem icon={Trash2} label="Clear Findings" desc="Remove old scan data" />
          </CardContent>
        </Card>
      </div>
    </PageContainer>
  );
}

function StatRow({ label, value }: { label: string; value: React.ReactNode }) {
  return (
    <div className="flex items-center justify-between border-b border-[#0B1220] pb-2 last:border-0">
      <span className="text-sm text-[#94A3B8]">{label}</span>
      <span className="text-sm font-medium text-[#F8FAFC]">{value}</span>
    </div>
  );
}

function ActionItem({ icon: Icon, label, desc }: { icon: React.ComponentType<{ className?: string }>; label: string; desc: string }) {
  return (
    <Button
      variant="outline"
      className="w-full justify-start gap-3 border-[#0B1220] bg-[#0B1220] text-[#F8FAFC] hover:bg-[#1E293B]"
    >
      <Icon className="h-4 w-4 text-[#3B82F6]" />
      <div className="text-left">
        <p className="text-sm font-medium">{label}</p>
        <p className="text-xs text-[#94A3B8]">{desc}</p>
      </div>
    </Button>
  );
}
