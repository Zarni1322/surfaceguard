import { type LucideIcon } from "lucide-react";
import { cn } from "@/lib/utils";

interface EmptyStateProps {
  icon?: LucideIcon;
  title: string;
  description?: string;
  action?: React.ReactNode;
  className?: string;
}

export default function EmptyState({ icon: Icon, title, description, action, className }: EmptyStateProps) {
  return (
    <div className={cn("flex items-center justify-center py-12 text-[#94A3B8]", className)}>
      <div className="text-center space-y-2">
        {Icon && <Icon className="h-10 w-10 mx-auto opacity-25" />}
        <p className="text-base">{title}</p>
        {description && <p className="text-sm">{description}</p>}
        {action && <div className="pt-2">{action}</div>}
      </div>
    </div>
  );
}
