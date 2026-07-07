import { cn } from "@/lib/utils";
import { LucideIcon } from "lucide-react";

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
    <div className="rounded-xl border border-[#1E293B] bg-[#1E293B] p-5 transition hover:border-[#3B82F6]/30">
      <div className="flex items-start justify-between">
        <div className="space-y-2">
          <p className="text-sm font-medium text-[#94A3B8]">{title}</p>
          {loading ? (
            <div className="h-8 w-20 animate-pulse rounded bg-[#0B1220]" />
          ) : (
            <p className={cn("text-2xl font-bold", color || "text-[#F8FAFC]")}>{value}</p>
          )}
          {subtitle && (
            <p className="text-xs text-[#94A3B8]">{subtitle}</p>
          )}
        </div>
        <div className="rounded-lg bg-[#0B1220] p-3" style={{ color: color || "#3B82F6" }}>
          <Icon className="h-5 w-5" />
        </div>
      </div>
    </div>
  );
}
