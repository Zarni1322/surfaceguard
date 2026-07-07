import { cn } from "@/lib/utils";
import type { LucideIcon } from "lucide-react";

interface StatCardProps {
  title: string;
  value: string | number;
  icon: LucideIcon;
  color?: string;
  subtitle?: string;
  loading?: boolean;
}

export default function StatCard({ title, value, icon: Icon, color, subtitle, loading }: StatCardProps) {
  return (
    <div className="rounded-lg border border-[#1E293B] bg-[#1E293B] p-3.5 transition hover:border-[#3B82F6]/30 h-full w-full">
      <div className="flex items-start justify-between gap-3">
        <div className="min-w-0">
          <p className="text-[11px] font-semibold text-[#64748B] uppercase tracking-wider truncate">{title}</p>
          {loading ? (
            <div className="h-6 w-16 mt-1 animate-pulse rounded bg-[#0B1220]" />
          ) : (
            <p className={cn("text-lg font-bold mt-0.5", color || "text-[#F8FAFC]")}>{value}</p>
          )}
          {subtitle && <p className="text-[11px] text-[#94A3B8] mt-0.5 truncate">{subtitle}</p>}
        </div>
        <div className="rounded-lg bg-[#0B1220] p-2 shrink-0" style={{ color: color || "#3B82F6" }}>
          <Icon className="h-4 w-4" />
        </div>
      </div>
    </div>
  );
}
