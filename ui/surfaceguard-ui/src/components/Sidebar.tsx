import { NavLink } from "react-router-dom";
import { cn } from "@/lib/utils";
import {
  LayoutDashboard,
  ScanSearch,
  Bug,
  Monitor,
  History,
  FileText,
  RefreshCw,
  Database,
  Settings,
  ChevronLeft,
  Shield,
  KeyRound,
  ShieldCheck,
  Globe,
} from "lucide-react";

const navItems = [
  { to: "/", icon: LayoutDashboard, label: "Dashboard" },
  { to: "/host-discovery", icon: ScanSearch, label: "Host Discovery" },
  { to: "/cve-discovery", icon: Bug, label: "Scan" },
  { to: "/credentials", icon: KeyRound, label: "Credentials" },
  { to: "/assessment", icon: ShieldCheck, label: "Assessment" },
  { to: "/assets", icon: Monitor, label: "Assets" },
  { to: "/easm", icon: Globe, label: "Attack Surface" },
  { to: "/scan-history", icon: History, label: "Scan History" },
  { to: "/updates", icon: RefreshCw, label: "Update Center" },
  { to: "/database", icon: Database, label: "Database" },
  { to: "/settings", icon: Settings, label: "Settings" },
];

interface SidebarProps {
  open: boolean;
  onToggle: () => void;
}

export default function Sidebar({ open, onToggle }: SidebarProps) {
  return (
    <aside
      className={cn(
        "flex flex-col bg-[#111827] border-r border-[#1E293B] transition-all duration-300",
        open ? "w-60" : "w-16"
      )}
    >
      {/* Logo */}
      <div className="flex h-16 items-center justify-between px-4 border-b border-[#1E293B]">
        {open && (
          <div className="flex items-center gap-2">
            <Shield className="h-6 w-6 text-[#3B82F6]" />
            <span className="font-semibold text-[#F8FAFC]">SurfaceGuard</span>
          </div>
        )}
        {!open && (
          <Shield className="h-6 w-6 text-[#3B82F6] mx-auto" />
        )}
        <button
          onClick={onToggle}
          className={cn(
            "p-1 rounded-md hover:bg-[#1E293B] text-[#94A3B8]",
            !open && "hidden"
          )}
        >
          <ChevronLeft className="h-4 w-4" />
        </button>
      </div>

      {/* Navigation */}
      <nav className="flex-1 space-y-1 p-3">
        {navItems.map((item) => (
          <NavLink
            key={item.to}
            to={item.to}
            end={item.to === "/"}
            className={({ isActive }) =>
              cn(
                "flex items-center gap-3 px-3 py-2.5 rounded-lg text-sm transition-colors",
                isActive
                  ? "bg-[#3B82F6]/10 text-[#3B82F6] font-medium"
                  : "text-[#94A3B8] hover:bg-[#1E293B] hover:text-[#F8FAFC]",
                !open && "justify-center px-2"
              )
            }
          >
            <item.icon className="h-5 w-5 shrink-0" />
            {open && <span>{item.label}</span>}
          </NavLink>
        ))}
      </nav>

      {/* Footer */}
      {open && (
        <div className="border-t border-[#1E293B] p-4">
          <p className="text-xs text-[#94A3B8]">
            SurfaceGuard v1.0
          </p>
          <p className="text-xs text-[#94A3B8]">
            Cyber Ops Academy
          </p>
        </div>
      )}
    </aside>
  );
}
