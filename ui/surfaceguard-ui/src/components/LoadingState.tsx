import { cn } from "@/lib/utils";

interface LoadingStateProps {
  className?: string;
  rows?: number;
}

function Skeleton({ className }: { className?: string }) {
  return <div className={cn("animate-pulse rounded bg-[#1E293B]", className)} />;
}

export default function LoadingState({ className, rows = 3 }: LoadingStateProps) {
  return (
    <div className={cn("space-y-3 p-4", className)}>
      {Array.from({ length: rows }).map((_, i) => (
        <Skeleton key={i} className="h-8 w-full" />
      ))}
    </div>
  );
}

export { Skeleton };
