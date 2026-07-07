import { useState, useEffect } from "react";
import { Card, CardContent } from "@/components/ui/card";
import { Monitor, ExternalLink } from "lucide-react";
import { listAssets } from "@/api/client";
import type { AssetDetail } from "@/types";
import { toast } from "sonner";
import { useNavigate } from "react-router-dom";

export default function AssetsPage() {
  const [assets, setAssets] = useState<AssetDetail[]>([]);
  const [loading, setLoading] = useState(true);
  const navigate = useNavigate();

  useEffect(() => {
    listAssets()
      .then(setAssets)
      .catch(() => toast.error("Failed to load assets"))
      .finally(() => setLoading(false));
  }, []);

  function assetIcon(type: string) {
    switch (type) {
      case "linux": return "🐧";
      case "windows": return "🪟";
      case "network_device": return "🌐";
      default: return "💻";
    }
  }

  function riskColor(score: number) {
    if (score >= 70) return "text-red-400";
    if (score >= 40) return "text-orange-400";
    if (score >= 20) return "text-yellow-400";
    return "text-green-400";
  }

  return (
    <div className="space-y-3 p-3 md:p-4 lg:p-5 xl:p-6">
      <div>
        <h1 className="text-2xl font-bold text-[#F8FAFC]">Asset Inventory</h1>
        <p className="text-sm text-[#94A3B8] mt-1">Discovered assets from authenticated assessments</p>
      </div>

      {loading ? (
        <p className="text-[#94A3B8]">Loading...</p>
      ) : assets.length === 0 ? (
        <Card className="bg-[#111827] border-[#1E293B]">
          <CardContent className="flex items-center justify-center py-20 text-[#94A3B8]">
            <div className="text-center space-y-3">
              <Monitor className="h-10 w-10 mx-auto opacity-30" />
              <p className="text-lg">No Assets Yet</p>
              <p className="text-sm">Run an authenticated assessment to discover assets</p>
            </div>
          </CardContent>
        </Card>
      ) : (
        <div className="overflow-x-auto">
          <table className="w-full">
            <thead>
              <tr className="border-b border-[#1E293B]">
                <th className="text-left p-3 text-[#94A3B8] text-sm font-medium">Hostname</th>
                <th className="text-left p-3 text-[#94A3B8] text-sm font-medium">IP</th>
                <th className="text-left p-3 text-[#94A3B8] text-sm font-medium">OS</th>
                <th className="text-left p-3 text-[#94A3B8] text-sm font-medium">Type</th>
                <th className="text-left p-3 text-[#94A3B8] text-sm font-medium">Risk</th>
                <th className="text-left p-3 text-[#94A3B8] text-sm font-medium">Last Scan</th>
                <th className="p-3"></th>
              </tr>
            </thead>
            <tbody>
              {assets.map((asset) => (
                <tr key={asset.id} className="border-b border-[#1E293B] hover:bg-[#1E293B]/50 cursor-pointer" onClick={() => navigate(`/assets?id=${asset.id}`)}>
                  <td className="p-3 text-[#F8FAFC] font-medium">{asset.hostname}</td>
                  <td className="p-3 text-[#94A3B8]">{asset.ip || "-"}</td>
                  <td className="p-3 text-[#94A3B8]">{asset.os || "-"}</td>
                  <td className="p-3 text-[#94A3B8]">{assetIcon(asset.asset_type)} {asset.asset_type}</td>
                  <td className={`p-3 font-medium ${riskColor(asset.risk_score)}`}>{asset.risk_score.toFixed(1)}</td>
                  <td className="p-3 text-[#64748B] text-sm">{asset.last_scan ? new Date(asset.last_scan).toLocaleDateString() : "-"}</td>
                  <td className="p-3"><ExternalLink className="h-4 w-4 text-[#3B82F6]" /></td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}
