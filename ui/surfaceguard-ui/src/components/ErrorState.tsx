import { AlertTriangle } from "lucide-react";
import { Button } from "@/components/ui/button";
import { cn } from "@/lib/utils";

interface ErrorStateProps {
  message: string;
  onRetry?: () => void;
  className?: string;
}

export default function ErrorState({ message, onRetry, className }: ErrorStateProps) {
  return (
    <div className={cn("flex items-center justify-center py-12", className)}>
      <div className="text-center space-y-3">
        <AlertTriangle className="h-10 w-10 mx-auto text-[#EF4444] opacity-60" />
        <p className="text-sm text-[#EF4444]">{message}</p>
        {onRetry && (
          <Button variant="outline" size="sm" onClick={onRetry} className="border-[#1E293B] text-[#94A3B8]">
            Retry
          </Button>
        )}
      </div>
    </div>
  );
}
