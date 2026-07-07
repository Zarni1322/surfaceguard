import { type ReactNode } from "react";
import { cn } from "@/lib/utils";

interface PageContainerProps {
  children: ReactNode;
  className?: string;
}

export default function PageContainer({ children, className }: PageContainerProps) {
  return (
    <div className={cn("grid grid-cols-12 gap-3 p-3 md:gap-4 md:p-4 lg:p-5 xl:p-6", className)}>
      {children}
    </div>
  );
}

// Span helpers for page grid columns — responsive: mobile full-width, tablet+ uses size
const spanMap: Record<number, string> = {
  1: "sm:col-span-1", 2: "sm:col-span-2", 3: "sm:col-span-3", 4: "sm:col-span-4",
  5: "sm:col-span-5", 6: "sm:col-span-6", 7: "sm:col-span-7", 8: "sm:col-span-8",
  9: "sm:col-span-9", 10: "sm:col-span-10", 11: "sm:col-span-11", 12: "col-span-12",
};

export function colSpan(size: 1 | 2 | 3 | 4 | 5 | 6 | 7 | 8 | 9 | 10 | 11 | 12, className?: string) {
  return cn("col-span-12 min-w-0", spanMap[size], className);
}
