import { useNavigate } from "react-router-dom";
import { useQuery } from "@tanstack/react-query";
import { Card, CardContent } from "@/components/ui/card";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { Badge } from "@/components/ui/badge";
import { History, Trash2 } from "lucide-react";
import { Button } from "@/components/ui/button";
import axios from "axios";
import { formatDate } from "@/lib/utils";
import PageContainer, { colSpan } from "@/components/PageContainer";
import PageHeader from "@/components/PageHeader";

const sevLabels = [
  { key: "critical", label: "Critical", color: "#EF4444", bg: "rgba(239,68,68,0.12)" },
  { key: "high",     label: "High",     color: "#F59E0B", bg: "rgba(245,158,11,0.12)" },
  { key: "medium",   label: "Medium",   color: "#3B82F6", bg: "rgba(59,130,246,0.12)" },
  { key: "low",      label: "Low",      color: "#22C55E", bg: "rgba(34,197,94,0.12)" },
  { key: "info",     label: "Info",     color: "#94A3B8", bg: "rgba(148,163,184,0.08)" },
];

function riskLabel(rec: ScanHistoryRecord): { label: string; color: string } {
  if (rec.critical > 0) return { label: "Critical", color: "#EF4444" };
  if (rec.high > 0)     return { label: "High",     color: "#F59E0B" };
  if (rec.medium > 0)   return { label: "Medium",   color: "#3B82F6" };
  if (rec.low > 0)      return { label: "Low",      color: "#22C55E" };
  if (rec.info > 0)     return { label: "Info",     color: "#94A3B8" };
  return { label: "None", color: "#64748B" };
}

export default function ScanHistoryPage() {
  const navigate = useNavigate();
  const { data: history, isLoading, error, refetch } = useQuery({
    queryKey: ["scan-history"],
    queryFn: async () => {
      const { data } = await axios.get("/api/scan-history");
      return data as ScanHistoryRecord[];
    },
    refetchInterval: 5000,
  });

  if (isLoading) {
    return (
      <PageContainer>
        <div className={colSpan(12)}>
        <h1 className="text-2xl font-bold text-[#F8FAFC]">Scan History</h1>
        <Card className="border-[#1E293B] bg-[#1E293B]">
          <CardContent className="py-20">
            <div className="flex items-center justify-center">
              <div className="h-8 w-8 animate-spin rounded-full border-4 border-[#3B82F6] border-t-transparent" />
            </div>
          </CardContent>
        </Card>
        </div>
      </PageContainer>
    );
  }

  if (error) {
    return (
      <PageContainer>
        <div className={colSpan(12)}>
        <PageHeader title="Scan History" />
        <Card className="border-[#EF4444]/30 bg-[#1E293B]">
          <CardContent className="pt-6">
            <p className="text-[#EF4444]">Failed to load scan history</p>
            <Button onClick={() => refetch()} variant="outline" size="sm" className="mt-2 border-[#0B1220]">
              Retry
            </Button>
          </CardContent>
        </Card>
        </div>
      </PageContainer>
    );
  }

  const records = history || [];

  return (
    <PageContainer>
      <div className={colSpan(12)}>
      <PageHeader title="Scan History" description={records.length > 0 ? `${records.length} scan(s) recorded` : "No scans recorded yet"}
        actions={records.length > 0 ? <Button
            variant="outline"
            size="sm"
            className="border-[#0B1220] text-[#94A3B8]"
            onClick={() => {
              axios.delete("/api/scan-history").then(() => refetch()).catch(() => {});
            }}
          >
            <Trash2 className="h-4 w-4 mr-2" /> Clear
          </Button> : undefined} />

      {records.length > 0 ? (
        <Card className="border-[#1E293B] bg-[#1E293B]">
          <CardContent className="pt-6">
            <Table>
              <TableHeader>
                <TableRow className="border-[#0B1220]">
                  <TableHead className="text-[#94A3B8]">Target</TableHead>
                  <TableHead className="text-[#94A3B8]">Date</TableHead>
                  <TableHead className="text-[#94A3B8]">Duration</TableHead>
                  <TableHead className="text-[#94A3B8]">Ports</TableHead>
                  <TableHead className="text-[#94A3B8]">Findings</TableHead>
                  <TableHead className="text-[#94A3B8]">Risk</TableHead>
                  <TableHead className="text-[#94A3B8]">Status</TableHead>
                  <TableHead className="text-[#94A3B8] w-10"></TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {records.map((rec, i) => {
                  const risk = riskLabel(rec);
                  return (
                  <TableRow key={i} className="border-[#0B1220] hover:bg-[#0B1220] cursor-pointer" onClick={() => navigate(`/scans/${rec.id}`)}>
                    <TableCell className="font-mono text-sm text-[#3B82F6] hover:underline" onClick={(e) => { e.stopPropagation(); navigate(`/scans/${rec.id}`); }}>{rec.target}</TableCell>
                    <TableCell className="text-sm text-[#F8FAFC]">{formatDate(rec.started_at)}</TableCell>
                    <TableCell className="text-sm text-[#F8FAFC]">{rec.duration}</TableCell>
                    <TableCell className="text-sm text-[#F8FAFC]">{rec.ports_found}</TableCell>
                    <TableCell className="text-sm text-[#F8FAFC]">
                      <div className="font-medium">{rec.findings} CVEs</div>
                      <div className="flex flex-wrap gap-1.5 mt-0.5">
                        {sevLabels.map((s) => (
                          <span
                            key={s.key}
                            className="inline-flex items-center gap-0.5 px-1.5 py-0.5 rounded text-[11px] font-semibold"
                            style={{ color: s.color, backgroundColor: s.bg }}
                          >
                            <span className="text-[10px]" aria-hidden>{s.label === "Critical" ? "🔴" : s.label === "High" ? "🟠" : s.label === "Medium" ? "🟡" : s.label === "Low" ? "🟢" : "⚪"}</span>
                            {(rec as any)[s.key] ?? 0}
                          </span>
                        ))}
                      </div>
                    </TableCell>
                    <TableCell>
                      <span
                        className="inline-flex items-center gap-1.5 px-2 py-0.5 rounded text-xs font-semibold"
                        style={{ color: risk.color, backgroundColor: risk.color === "#EF4444" ? "rgba(239,68,68,0.12)" : risk.color === "#F59E0B" ? "rgba(245,158,11,0.12)" : risk.color === "#3B82F6" ? "rgba(59,130,246,0.12)" : risk.color === "#22C55E" ? "rgba(34,197,94,0.12)" : "rgba(148,163,184,0.08)" }}
                      >
                        {risk.label}
                      </span>
                    </TableCell>
                    <TableCell>
                      <Badge
                        variant="outline"
                        className={
                          rec.status === "completed"
                            ? "border-[#22C55E] text-[#22C55E]"
                            : "border-[#F59E0B] text-[#F59E0B]"
                        }
                      >
                        {rec.status}
                      </Badge>
                    </TableCell>
                    <TableCell>
                      <button
                        onClick={(e) => { e.stopPropagation(); e.preventDefault();
                          axios.delete(`/api/scan-history?id=${rec.id}`).then(() => refetch());
                        }}
                        className="text-[#64748B] hover:text-[#EF4444] transition-colors p-1"
                        title="Delete scan record"
                      >
                        <Trash2 className="h-4 w-4" />
                      </button>
                    </TableCell>
                  </TableRow>
                  );
                })}
              </TableBody>
            </Table>
          </CardContent>
        </Card>
      ) : (
        <Card className="border-[#1E293B] bg-[#1E293B]">
          <CardContent className="flex items-center justify-center py-20 text-[#94A3B8]">
            <div className="text-center space-y-3">
              <History className="h-12 w-12 mx-auto opacity-20" />
              <p className="text-lg">No scan history</p>
              <p className="text-sm">Run a CVE Discovery scan to see results here</p>
            </div>
          </CardContent>
        </Card>
      )}
      </div>
    </PageContainer>
  );
}

interface ScanHistoryRecord {
  id: number;
  target: string;
  started_at: string;
  duration: string;
  ports_found: number;
  findings: number;
  risk_score: number;
  status: string;
  critical: number;
  high: number;
  medium: number;
  low: number;
  info: number;
}
