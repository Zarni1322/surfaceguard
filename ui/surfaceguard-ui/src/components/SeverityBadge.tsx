import { cn } from "@/lib/utils";

type Severity = "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "NONE";

const severityConfig: Record<string, { bg: string; text: string; border: string; dot: string }> = {
  CRITICAL: { bg: "bg-red-500/10", text: "text-red-400", border: "border-red-500/30", dot: "bg-red-500" },
  HIGH:     { bg: "bg-orange-500/10", text: "text-orange-400", border: "border-orange-500/30", dot: "bg-orange-500" },
  MEDIUM:   { bg: "bg-yellow-500/10", text: "text-yellow-400", border: "border-yellow-500/30", dot: "bg-yellow-500" },
  LOW:      { bg: "bg-blue-500/10", text: "text-blue-400", border: "border-blue-500/30", dot: "bg-blue-500" },
  NONE:     { bg: "bg-gray-500/10", text: "text-gray-400", border: "border-gray-500/30", dot: "bg-gray-500" },
};

interface SeverityBadgeProps {
  severity: string;
  showDot?: boolean;
  className?: string;
}

export default function SeverityBadge({ severity, showDot = true, className }: SeverityBadgeProps) {
  const cfg = severityConfig[severity.toUpperCase()] || severityConfig.NONE;
  return (
    <span className={cn("inline-flex items-center gap-1.5 rounded-full px-2.5 py-0.5 text-[11px] font-semibold border", cfg.bg, cfg.text, cfg.border, className)}>
      {showDot && <span className={cn("h-1.5 w-1.5 rounded-full", cfg.dot)} />}
      {severity}
    </span>
  );
}

export function severityColor(severity: string): string {
  return severityConfig[severity.toUpperCase()]?.text || severityConfig.NONE.text;
}

export function severityDot(severity: string): string {
  return severityConfig[severity.toUpperCase()]?.dot || severityConfig.NONE.dot;
}
