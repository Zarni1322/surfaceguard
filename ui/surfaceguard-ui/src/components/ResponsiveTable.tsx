import { type ReactNode } from "react";
import { cn } from "@/lib/utils";

interface ResponsiveTableProps {
  children: ReactNode;
  className?: string;
}

export default function ResponsiveTable({ children, className }: ResponsiveTableProps) {
  return (
    <div className={cn("overflow-x-auto -mx-3 md:-mx-0", className)}>
      <table className="w-full min-w-[600px]">
        {children}
      </table>
    </div>
  );
}

interface TableHeadProps {
  children: ReactNode;
  className?: string;
}

export function TableHead({ children, className }: TableHeadProps) {
  return (
    <thead className={cn("sticky top-0 z-10", className)}>
      {children}
    </thead>
  );
}

interface TableRowProps {
  children: ReactNode;
  className?: string;
  onClick?: () => void;
}

export function TableRow({ children, className, onClick }: TableRowProps) {
  return (
    <tr className={cn("border-b border-[#1E293B] hover:bg-[#1E293B]/50", onClick ? "cursor-pointer" : "", className)}
        onClick={onClick}>
      {children}
    </tr>
  );
}

interface TableHeaderCellProps {
  children: ReactNode;
  className?: string;
}

export function TableHeaderCell({ children, className }: TableHeaderCellProps) {
  return (
    <th className={cn("text-left p-3 text-[#94A3B8] text-xs font-medium uppercase tracking-wider", className)}>
      {children}
    </th>
  );
}

interface TableCellProps {
  children: ReactNode;
  className?: string;
}

export function TableCell({ children, className }: TableCellProps) {
  return (
    <td className={cn("p-3 text-sm text-[#F8FAFC]", className)}>
      {children}
    </td>
  );
}
