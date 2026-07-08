import { useState, useEffect } from "react";
import { Button } from "@/components/ui/button";
import { Card, CardContent } from "@/components/ui/card";
import { Monitor, Trash2 } from "lucide-react";
import { listAssets, deleteAssessmentHistory } from "@/api/client";
import type { AssetDetail } from "@/types";
import { toast } from "sonner";
import PageContainer, { colSpan } from "@/components/PageContainer";
import PageHeader from "@/components/PageHeader";

export default function AssetsPage() {
  const [assets, setAssets] = useState<AssetDetail[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => { loadAssets(); }, []);

  async function loadAssets() {
    try {
      setAssets(await listAssets());
    } catch { toast.error("Failed to load assets"); } finally { setLoading(false); }
  }

  async function handleReset() {
    if (assets.length === 0) { toast.info("No assets to reset"); return; }
    if (!window.confirm("Reset all asset inventory? This cannot be undone.")) return;
    try {
      await deleteAssessmentHistory(); // clears asset_inventory too
      toast.success("Asset inventory reset");
      setAssets([]);
    } catch { toast.error("Reset failed"); }
  }

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
    <PageContainer>
      <div className={colSpan(12)}>
        <PageHeader title="Asset Inventory" description="Discovered assets from authenticated assessments"
          actions={assets.length > 0 ? <Button onClick={handleReset} variant="outline" size="sm" className="border-red-500/30 text-red-400 hover:bg-red-500/10"><Trash2 className="h-4 w-4 mr-1" />Reset</Button> : undefined} />
      </div>

      <div className={colSpan(12)}>
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
                <tr key={asset.id} className="border-b border-[#1E293B] hover:bg-[#1E293B]/50">
                  <td className="p-3 text-[#F8FAFC] font-medium">{asset.hostname}</td>
                  <td className="p-3 text-[#94A3B8]">{asset.ip || "-"}</td>
                  <td className="p-3 text-[#94A3B8]">{asset.os || "-"}</td>
                  <td className="p-3 text-[#94A3B8]">{assetIcon(asset.asset_type)} {asset.asset_type}</td>
                  <td className={`p-3 font-medium ${riskColor(asset.risk_score)}`}>{asset.risk_score.toFixed(1)}</td>
                  <td className="p-3 text-[#64748B] text-sm">{asset.last_scan ? new Date(asset.last_scan).toLocaleDateString() : "-"}</td>
                  <td className="p-3"></td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
      </div>
    </PageContainer>
  );
}
