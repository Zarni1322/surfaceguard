import { Card, CardContent } from "@/components/ui/card";
import { Monitor } from "lucide-react";

export default function AssetsPage() {
  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-bold text-[#F8FAFC]">Assets</h1>
        <p className="text-sm text-[#94A3B8] mt-1">Discovered assets and inventory</p>
      </div>
      <Card className="border-[#1E293B] bg-[#1E293B]">
        <CardContent className="flex items-center justify-center py-20 text-[#94A3B8]">
          <div className="text-center space-y-3">
            <Monitor className="h-10 w-10 mx-auto opacity-30" />
            <p className="text-lg">Coming Soon</p>
            <p className="text-sm">This module is under development</p>
          </div>
        </CardContent>
      </Card>
    </div>
  );
}
