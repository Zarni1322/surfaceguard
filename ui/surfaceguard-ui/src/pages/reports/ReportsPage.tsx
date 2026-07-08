import { useState } from "react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { toast } from "sonner";
import PageContainer from "@/components/PageContainer";
import PageHeader from "@/components/PageHeader";
import {
  FileText,
  Download,
  FileJson,
  FileSpreadsheet,
  FileImage,
  Globe,
  Loader2,
  ExternalLink,
  CheckCircle2,
  History,
} from "lucide-react";

type ReportFormat = "html" | "json" | "xlsx" | "pdf";

const formats: { key: ReportFormat; label: string; icon: React.ElementType; desc: string; color: string }[] = [
  { key: "html", label: "HTML", icon: FileText, desc: "Full report with styling", color: "#3B82F6" },
  { key: "json", label: "JSON", icon: FileJson, desc: "Machine-readable data", color: "#22C55E" },
  { key: "xlsx", label: "CSV", icon: FileSpreadsheet, desc: "Spreadsheet-compatible", color: "#F59E0B" },
  { key: "pdf", label: "PDF", icon: FileImage, desc: "Printable document", color: "#EF4444" },
];

export default function ReportsPage() {
  const [target, setTarget] = useState("");
  const [generating, setGenerating] = useState<string | null>(null);
  const [recentReports, setRecentReports] = useState<{ target: string; format: string; time: string }[]>([]);

  const handleGenerate = async (format: ReportFormat) => {
    if (!target.trim()) {
      toast.error("Enter a target first");
      return;
    }
    setGenerating(format);

    try {
      const resp = await fetch(`/api/report?target=${encodeURIComponent(target.trim())}&format=${format}`);
      if (!resp.ok) {
        const text = await resp.text();
        throw new Error(text || resp.statusText);
      }

      const blob = await resp.blob();
      const ext = format === "xlsx" ? "csv" : format;
      const filename = `surfaceguard-report-${target.trim()}.${ext}`;
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = filename;
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      URL.revokeObjectURL(url);

      setRecentReports((prev) => [
        { target: target.trim(), format, time: new Date().toLocaleTimeString() },
        ...prev.slice(0, 9),
      ]);

      toast.success(`${format.toUpperCase()} report downloaded`);
    } catch (err: any) {
      toast.error(err.message || "Failed to generate report");
    } finally {
      setGenerating(null);
    }
  };

  return (
    <PageContainer>
      <PageHeader title="Reports" description="Generate and download vulnerability assessment reports" />

      {/* Target Input */}
      <Card className="border-[#1E293B] bg-[#1E293B]">
        <CardContent className="pt-6">
          <div className="flex gap-3">
            <div className="flex-1">
              <Input
                placeholder="Target (e.g., example.com, 10.0.0.1)"
                value={target}
                onChange={(e) => setTarget(e.target.value)}
                className="border-[#0B1220] bg-[#0B1220] text-[#F8FAFC] placeholder:text-[#94A3B8] font-mono"
              />
            </div>
          </div>
        </CardContent>
      </Card>

      {/* Format Selection */}
      <div className="grid gap-3 grid-cols-2 lg:grid-cols-4">
        {formats.map((fmt) => (
          <button
            key={fmt.key}
            onClick={() => handleGenerate(fmt.key)}
            disabled={generating !== null || !target.trim()}
            className="group rounded-xl border border-[#1E293B] bg-[#1E293B] p-6 text-left transition-all hover:border-[#3B82F6]/30 hover:bg-[#1E293B]/80 disabled:opacity-50 disabled:cursor-not-allowed"
          >
            <div className="flex items-start justify-between">
              <div
                className="rounded-lg p-3 transition group-hover:scale-110"
                style={{ background: `${fmt.color}15` }}
              >
                {generating === fmt.key ? (
                  <Loader2 className="h-6 w-6 animate-spin" style={{ color: fmt.color }} />
                ) : (
                  <fmt.icon className="h-6 w-6" style={{ color: fmt.color }} />
                )}
              </div>
              <Badge
                variant="outline"
                className="text-[10px]"
                style={{ borderColor: fmt.color, color: fmt.color }}
              >
                {fmt.label}
              </Badge>
            </div>
            <p className="mt-4 font-semibold text-[#F8FAFC]">{fmt.label} Report</p>
            <p className="mt-1 text-sm text-[#94A3B8]">{fmt.desc}</p>

            <Button
              variant="outline"
              size="sm"
              disabled={generating !== null || !target.trim()}
              className="mt-4 w-full border-[#0B1220] bg-[#0B1220] text-[#F8FAFC] hover:bg-[#0B1220]/80"
              onClick={(e) => {
                e.stopPropagation();
                handleGenerate(fmt.key);
              }}
            >
              {generating === fmt.key ? (
                <Loader2 className="h-4 w-4 mr-2 animate-spin" />
              ) : (
                <Download className="h-4 w-4 mr-2" />
              )}
              {generating === fmt.key ? "Generating..." : `Download ${fmt.label}`}
            </Button>
          </button>
        ))}
      </div>

      {/* Recent Reports */}
      {recentReports.length > 0 && (
        <Card className="border-[#1E293B] bg-[#1E293B]">
          <CardHeader>
            <CardTitle className="text-lg text-[#F8FAFC] flex items-center gap-2">
              <History className="h-5 w-5 text-[#94A3B8]" />
              Recent Reports
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div className="space-y-2">
              {recentReports.map((r, i) => (
                <div
                  key={i}
                  className="flex items-center justify-between rounded-lg border border-[#0B1220] bg-[#0B1220] p-3"
                >
                  <div className="flex items-center gap-3">
                    <CheckCircle2 className="h-4 w-4 text-[#22C55E]" />
                    <span className="font-mono text-sm text-[#F8FAFC]">{r.target}</span>
                    <Badge
                      variant="outline"
                      className="text-[10px]"
                      style={{
                        color: formats.find((f) => f.key === r.format)?.color || "#94A3B8",
                        borderColor: formats.find((f) => f.key === r.format)?.color || "#1E293B",
                      }}
                    >
                      {r.format.toUpperCase()}
                    </Badge>
                  </div>
                  <span className="text-xs text-[#94A3B8]">{r.time}</span>
                </div>
              ))}
            </div>
          </CardContent>
        </Card>
      )}

      {/* Empty State */}
      {recentReports.length === 0 && (
        <Card className="border-[#1E293B] bg-[#1E293B]">
          <CardContent className="flex items-center justify-center py-20 text-[#94A3B8]">
            <div className="text-center space-y-3">
              <FileText className="h-12 w-12 mx-auto opacity-20" />
              <p className="text-lg">No reports generated yet</p>
              <p className="text-sm">
                Enter a target above and choose a format to generate your first report
              </p>
            </div>
          </CardContent>
        </Card>
      )}
    </PageContainer>
  );
}
