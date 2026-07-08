import { type ReactNode } from "react";
import { cn } from "@/lib/utils";

interface PageGridProps {
  children: ReactNode;
  className?: string;
}

export function PageGrid({ children, className }: PageGridProps) {
  return (
    <div className={cn("grid grid-cols-12 gap-3 md:gap-4 lg:gap-5", className)}>
      {children}
    </div>
  );
}

interface GridColProps {
  children: ReactNode;
  cols?: 1 | 2 | 3 | 4 | 5 | 6 | 7 | 8 | 9 | 10 | 11 | 12;
  className?: string;
}

const spanMap: Record<number, string> = {
  1: "sm:col-span-1", 2: "sm:col-span-2", 3: "sm:col-span-3", 4: "sm:col-span-4",
  5: "sm:col-span-5", 6: "sm:col-span-6", 7: "sm:col-span-7", 8: "sm:col-span-8",
  9: "sm:col-span-9", 10: "sm:col-span-10", 11: "sm:col-span-11", 12: "col-span-12",
};

export function GridCol({ children, cols = 12, className }: GridColProps) {
  return (
    <div className={cn("col-span-12 min-w-0", spanMap[cols], className)}>
      {children}
    </div>
  );
}

// Legacy colSpan helper — kept for backward compatibility with existing pages
export function colSpan(size: 1 | 2 | 3 | 4 | 5 | 6 | 7 | 8 | 9 | 10 | 11 | 12, className?: string) {
  return cn("col-span-12 min-w-0", spanMap[size], className);
}
