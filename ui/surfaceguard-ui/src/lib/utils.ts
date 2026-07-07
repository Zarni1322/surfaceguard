import { type ClassValue, clsx } from "clsx";
import { twMerge } from "tailwind-merge";

export function cn(...inputs: ClassValue[]) {
  return twMerge(clsx(inputs));
}

export function severityColor(severity: string): string {
  switch (severity.toUpperCase()) {
    case "CRITICAL": return "#EF4444";
    case "HIGH":     return "#F59E0B";
    case "MEDIUM":   return "#3B82F6";
    case "LOW":      return "#22C55E";
    default:         return "#94A3B8";
  }
}

export function severityBg(severity: string): string {
  switch (severity.toUpperCase()) {
    case "CRITICAL": return "rgba(239,68,68,0.12)";
    case "HIGH":     return "rgba(245,158,11,0.12)";
    case "MEDIUM":   return "rgba(59,130,246,0.12)";
    case "LOW":      return "rgba(34,197,94,0.12)";
    default:         return "rgba(148,163,184,0.08)";
  }
}

export function formatDate(iso: string): string {
  if (!iso || iso.startsWith("0001")) return "N/A";
  const d = new Date(iso);
  return d.toLocaleDateString("en-US", {
    year: "numeric", month: "short", day: "numeric",
    hour: "2-digit", minute: "2-digit",
  });
}

export function shortDate(iso: string): string {
  if (!iso || iso.startsWith("0001")) return "N/A";
  const d = new Date(iso);
  return d.toLocaleDateString("en-US", { month: "short", day: "numeric" });
}

export function truncate(str: string, len: number): string {
  if (str.length <= len) return str;
  return str.slice(0, len) + "...";
}
