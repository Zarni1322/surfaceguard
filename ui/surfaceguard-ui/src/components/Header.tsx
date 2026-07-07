import { Menu, Shield } from "lucide-react";
import { Button } from "@/components/ui/button";

interface HeaderProps {
  onMenuClick: () => void;
}

export default function Header({ onMenuClick }: HeaderProps) {
  return (
    <header className="flex h-11 items-center justify-between border-b border-[#1E293B] bg-[#0B1220] px-3 md:px-4 shrink-0">
      <div className="flex items-center gap-3">
        <Button
          variant="ghost"
          size="icon"
          onClick={onMenuClick}
          className="text-[#94A3B8] hover:text-[#F8FAFC] h-8 w-8"
        >
          <Menu className="h-4 w-4" />
        </Button>
        <Shield className="h-4 w-4 text-[#3B82F6] hidden md:block" />
      </div>
      <div className="flex items-center gap-3">
        <div className="flex items-center gap-1.5">
          <div className="h-1.5 w-1.5 rounded-full bg-[#22C55E]" />
          <span className="text-xs text-[#94A3B8]">Online</span>
        </div>
      </div>
    </header>
  );
}
