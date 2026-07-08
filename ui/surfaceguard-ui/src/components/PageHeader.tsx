import { type ReactNode } from "react";
import { cn } from "@/lib/utils";

interface PageHeaderProps {
  title: string;
  description?: string;
  actions?: ReactNode;
  className?: string;
}

export default function PageHeader({ title, description, actions, className }: PageHeaderProps) {
  return (
    <div className={cn("flex flex-wrap items-center justify-between gap-3 mb-4 lg:mb-5", className)}>
      <div className="min-w-0">
        <h1 className="text-xl lg:text-2xl font-bold text-[#F8FAFC] truncate">{title}</h1>
        {description && <p className="text-xs lg:text-sm text-[#94A3B8] mt-0.5">{description}</p>}
      </div>
      {actions && <div className="flex items-center gap-2 shrink-0">{actions}</div>}
    </div>
  );
}
