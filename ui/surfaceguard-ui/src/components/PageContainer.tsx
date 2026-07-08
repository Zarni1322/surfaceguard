import { type ReactNode } from "react";
import { cn } from "@/lib/utils";

interface PageContainerProps {
  children: ReactNode;
  className?: string;
}

export default function PageContainer({ children, className }: PageContainerProps) {
  return (
    <div className={cn("p-3 md:p-4 lg:p-5 xl:p-6 2xl:p-8", className)}>
      {children}
    </div>
  );
}

// Backward compatibility re-exports
export { PageGrid, GridCol, colSpan } from "./PageGrid";
