import { type ReactNode } from "react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { cn } from "@/lib/utils";

interface ContentCardProps {
  title?: string;
  description?: string;
  actions?: ReactNode;
  children: ReactNode;
  className?: string;
  contentClassName?: string;
}

export default function ContentCard({ title, description, actions, children, className, contentClassName }: ContentCardProps) {
  return (
    <Card className={cn("bg-[#111827] border-[#1E293B]", className)}>
      {(title || actions) && (
        <CardHeader className={cn("pb-3 flex flex-row items-center justify-between", description ? "" : "")}>
          <div className="min-w-0">
            {title && <CardTitle className="text-base text-[#F8FAFC]">{title}</CardTitle>}
            {description && <p className="text-xs text-[#94A3B8] mt-0.5">{description}</p>}
          </div>
          {actions && <div className="flex items-center gap-2 shrink-0">{actions}</div>}
        </CardHeader>
      )}
      <CardContent className={cn(contentClassName)}>
        {children}
      </CardContent>
    </Card>
  );
}
