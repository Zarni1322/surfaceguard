import { Menu } from "lucide-react";
import { Button } from "@/components/ui/button";

interface HeaderProps {
  onMenuClick: () => void;
}

export default function Header({ onMenuClick }: HeaderProps) {
  return (
    <header className="flex h-16 items-center justify-between border-b border-[#1E293B] bg-[#0B1220] px-6">
      <div className="flex items-center gap-4">
        <Button
          variant="ghost"
          size="icon"
          onClick={onMenuClick}
          className="text-[#94A3B8] hover:text-[#F8FAFC]"
        >
          <Menu className="h-5 w-5" />
        </Button>
        <div className="flex items-center gap-2">
          <div className="h-2 w-2 rounded-full bg-[#22C55E]" />
          <span className="text-sm text-[#94A3B8]">System Online</span>
        </div>
      </div>
      <div className="flex items-center gap-4">
        <span className="text-sm text-[#94A3B8]">Cyber Ops Academy</span>
      </div>
    </header>
  );
}
