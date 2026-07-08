import { useQuery } from "@tanstack/react-query";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { Badge } from "@/components/ui/badge";
import { History, Clock, Trash2 } from "lucide-react";
import { Button } from "@/components/ui/button";
import axios from "axios";
import { formatDate, severityColor } from "@/lib/utils";
import PageContainer from "@/components/PageContainer";
import PageHeader from "@/components/PageHeader";

export default function ScanHistoryPage() {
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
        <h1 className="text-2xl font-bold text-[#F8FAFC]">Scan History</h1>
        <Card className="border-[#1E293B] bg-[#1E293B]">
          <CardContent className="py-20">
            <div className="flex items-center justify-center">
              <div className="h-8 w-8 animate-spin rounded-full border-4 border-[#3B82F6] border-t-transparent" />
            </div>
          </CardContent>
        </Card>
      </PageContainer>
    );
  }

  if (error) {
    return (
      <PageContainer>
        <PageHeader title="Scan History" />
        <Card className="border-[#EF4444]/30 bg-[#1E293B]">
          <CardContent className="pt-6">
            <p className="text-[#EF4444]">Failed to load scan history</p>
            <Button onClick={() => refetch()} variant="outline" size="sm" className="mt-2 border-[#0B1220]">
              Retry
            </Button>
          </CardContent>
        </Card>
      </PageContainer>
    );
  }

  const records = history || [];

  return (
    <PageContainer>
      <PageHeader title="Scan History" description={records.length > 0 ? `${records.length} scan(s) recorded` : "No scans recorded yet"}
        actions={records.length > 0 ? <Button
            variant="outline"
            size="sm"
            className="border-[#0B1220] text-[#94A3B8]"
            onClick={() => {
              localStorage.removeItem("scan-history");
              refetch();
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
                </TableRow>
              </TableHeader>
              <TableBody>
                {records.map((rec, i) => (
                  <TableRow key={i} className="border-[#0B1220] hover:bg-[#0B1220]">
                    <TableCell className="font-mono text-sm text-[#3B82F6]">{rec.target}</TableCell>
                    <TableCell className="text-sm text-[#F8FAFC]">{formatDate(rec.started_at)}</TableCell>
                    <TableCell className="text-sm text-[#F8FAFC]">{rec.duration}</TableCell>
                    <TableCell className="text-sm text-[#F8FAFC]">{rec.ports_found}</TableCell>
                    <TableCell className="text-sm text-[#F8FAFC]">{rec.findings}</TableCell>
                    <TableCell>
                      <span
                        className="font-mono text-sm font-bold"
                        style={{ color: rec.risk_score > 70 ? "#EF4444" : rec.risk_score > 40 ? "#F59E0B" : "#22C55E" }}
                      >
                        {rec.risk_score.toFixed(0)}
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
                  </TableRow>
                ))}
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
    </PageContainer>
  );
}

interface ScanHistoryRecord {
  target: string;
  started_at: string;
  duration: string;
  ports_found: number;
  findings: number;
  risk_score: number;
  status: string;
}
