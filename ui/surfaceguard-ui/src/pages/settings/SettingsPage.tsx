import { useState } from "react";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Separator } from "@/components/ui/separator";
import { toast } from "sonner";
import axios from "axios";
import {
  Settings,
  Save,
  RotateCcw,
  Info,
  Database,
  Activity,
  Shield,
  Server,
  RefreshCw,
  CheckCircle2,
  AlertCircle,
} from "lucide-react";

interface SysInfo {
  version: string;
  build_date: string;
  db_version: string;
  feed_status: string;
  last_update: string;
  cve_count: number;
  kev_count: number;
  epss_count: number;
}

export default function SettingsPage() {
  const queryClient = useQueryClient();
  const [workers, setWorkers] = useState("");
  const [timeout, setTimeout_] = useState("");
  const [logLevel, setLogLevel] = useState("info");
  const [logFormat, setLogFormat] = useState("text");
  const [cvssThreshold, setCvssThreshold] = useState("");

  const { data: sysInfo, isLoading: sysLoading, refetch: refetchSys } = useQuery<SysInfo>({
    queryKey: ["system-info"],
    queryFn: async () => {
      const { data } = await axios.get("/api/system");
      return data;
    },
    refetchInterval: 30000,
  });

  const { data: config, isLoading: configLoading } = useQuery({
    queryKey: ["settings-config"],
    queryFn: async () => {
      const { data } = await axios.get("/api/settings");
      // Set form defaults when config loads
      if (data) {
        setWorkers(data.scan?.workers?.toString() || "100");
        setTimeout_(data.scan?.timeout || "3s");
        setLogLevel(data.logging?.level || "info");
        setLogFormat(data.logging?.format || "text");
        setCvssThreshold(data.report?.cvss_threshold?.toString() || "0");
      }
      return data;
    },
  });

  const handleSave = async () => {
    try {
      await axios.put("/api/settings", {
        scan: {
          workers: parseInt(workers) || 100,
          timeout: timeout || "3s",
        },
        logging: {
          level: logLevel,
          format: logFormat,
        },
        report: {
          cvss_threshold: parseFloat(cvssThreshold) || 0,
        },
      });
      toast.success("Settings saved");
      queryClient.invalidateQueries({ queryKey: ["settings-config"] });
    } catch (err: any) {
      toast.error(err.message || "Failed to save settings");
    }
  };

  const handleReset = () => {
    setWorkers("100");
    setTimeout_("3s");
    setLogLevel("info");
    setLogFormat("text");
    setCvssThreshold("0");
    toast.info("Settings reset to defaults");
  };

  return (
    <div className="space-y-3 p-3 md:p-4 lg:p-5 xl:p-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-[#F8FAFC]">Settings</h1>
          <p className="text-sm text-[#94A3B8] mt-1">System configuration</p>
        </div>
        <div className="flex gap-2">
          <Button
            variant="outline"
            size="sm"
            onClick={handleReset}
            className="border-[#0B1220] text-[#94A3B8]"
          >
            <RotateCcw className="h-4 w-4 mr-2" />
            Reset
          </Button>
          <Button
            onClick={handleSave}
            size="sm"
            className="bg-[#3B82F6] hover:bg-[#2563EB] text-white"
          >
            <Save className="h-4 w-4 mr-2" />
            Save Settings
          </Button>
        </div>
      </div>

      <div className="grid gap-3 grid-cols-1 lg:grid-cols-2">
        {/* System Information */}
        <Card className="border-[#1E293B] bg-[#1E293B] lg:col-span-2">
          <CardHeader>
            <CardTitle className="text-lg text-[#F8FAFC] flex items-center gap-2">
              <Info className="h-5 w-5 text-[#3B82F6]" />
              System Information
            </CardTitle>
          </CardHeader>
          <CardContent>
            {sysLoading ? (
              <div className="h-20 flex items-center justify-center">
                <div className="h-6 w-6 animate-spin rounded-full border-2 border-[#3B82F6] border-t-transparent" />
              </div>
            ) : (
              <div className="grid gap-3 grid-cols-1 sm:grid-cols-2 lg:grid-cols-4">
                <SysInfoCard label="Version" value={sysInfo?.version || "—"} icon={Shield} color="#3B82F6" />
                <SysInfoCard label="DB Schema" value={`v${sysInfo?.db_version || "—"}`} icon={Database} color="#22C55E" />
                <SysInfoCard label="Feed Status" value={sysInfo?.feed_status || "Unknown"} icon={Activity} color="#F59E0B" />
                <SysInfoCard label="Last Update" value={sysInfo?.last_update ? new Date(sysInfo.last_update).toLocaleDateString() : "N/A"} icon={RefreshCw} color="#94A3B8" />
              </div>
            )}
          </CardContent>
        </Card>

        {/* Scan Settings */}
        <Card className="border-[#1E293B] bg-[#1E293B]">
          <CardHeader>
            <CardTitle className="text-lg text-[#F8FAFC] flex items-center gap-2">
              <Server className="h-5 w-5 text-[#3B82F6]" />
              Scan Configuration
            </CardTitle>
          </CardHeader>
          <CardContent className="space-y-3">
            <SettingField label="Workers" desc="Concurrent scan threads">
              <Input
                type="number"
                value={workers}
                onChange={(e) => setWorkers(e.target.value)}
                className="border-[#0B1220] bg-[#0B1220] text-[#F8FAFC] w-24"
              />
            </SettingField>
            <SettingField label="Timeout" desc="Per-port connection timeout">
              <Input
                value={timeout}
                onChange={(e) => setTimeout_(e.target.value)}
                className="border-[#0B1220] bg-[#0B1220] text-[#F8FAFC] w-24 font-mono"
                placeholder="3s"
              />
            </SettingField>
            <SettingField label="CVSS Threshold" desc="Minimum CVSS score to report">
              <Input
                type="number"
                step="0.1"
                min="0"
                max="10"
                value={cvssThreshold}
                onChange={(e) => setCvssThreshold(e.target.value)}
                className="border-[#0B1220] bg-[#0B1220] text-[#F8FAFC] w-24"
              />
            </SettingField>
          </CardContent>
        </Card>

        {/* Logging Settings */}
        <Card className="border-[#1E293B] bg-[#1E293B]">
          <CardHeader>
            <CardTitle className="text-lg text-[#F8FAFC] flex items-center gap-2">
              <Activity className="h-5 w-5 text-[#22C55E]" />
              Logging
            </CardTitle>
          </CardHeader>
          <CardContent className="space-y-3">
            <SettingField label="Log Level" desc="Verbosity of logs">
              <select
                value={logLevel}
                onChange={(e) => setLogLevel(e.target.value)}
                className="border border-[#0B1220] bg-[#0B1220] text-[#F8FAFC] rounded-md px-3 py-2 text-sm w-28"
              >
                <option value="debug">debug</option>
                <option value="info">info</option>
                <option value="warn">warn</option>
                <option value="error">error</option>
              </select>
            </SettingField>
            <SettingField label="Log Format" desc="Output format">
              <select
                value={logFormat}
                onChange={(e) => setLogFormat(e.target.value)}
                className="border border-[#0B1220] bg-[#0B1220] text-[#F8FAFC] rounded-md px-3 py-2 text-sm w-28"
              >
                <option value="text">text</option>
                <option value="json">json</option>
              </select>
            </SettingField>
          </CardContent>
        </Card>

        {/* Database Stats */}
        <Card className="border-[#1E293B] bg-[#1E293B]">
          <CardHeader>
            <CardTitle className="text-lg text-[#F8FAFC] flex items-center gap-2">
              <Database className="h-5 w-5 text-[#F59E0B]" />
              Database Statistics
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div className="space-y-3">
              <DBStatRow label="CVEs" value={(sysInfo?.cve_count ?? 0).toLocaleString()} color="#3B82F6" />
              <DBStatRow label="KEV" value={(sysInfo?.kev_count ?? 0).toLocaleString()} color="#F59E0B" />
              <DBStatRow label="EPSS" value={(sysInfo?.epss_count ?? 0).toLocaleString()} color="#22C55E" />
              <Separator className="bg-[#0B1220]" />
              <DBStatRow label="Total Records" value={((sysInfo?.cve_count ?? 0) + (sysInfo?.kev_count ?? 0) + (sysInfo?.epss_count ?? 0)).toLocaleString()} color="#F8FAFC" />
            </div>
          </CardContent>
        </Card>

        {/* About */}
        <Card className="border-[#1E293B] bg-[#1E293B]">
          <CardHeader>
            <CardTitle className="text-lg text-[#F8FAFC] flex items-center gap-2">
              <Shield className="h-5 w-5 text-[#8B5CF6]" />
              About
            </CardTitle>
          </CardHeader>
          <CardContent className="space-y-2 text-sm text-[#94A3B8]">
            <p><span className="text-[#F8FAFC]">SurfaceGuard</span> — Enterprise Infrastructure Vulnerability Scanner</p>
            <p>Organization: Cyber Ops Academy</p>
            <p>Author: Han Niux</p>
            <p>Version: {sysInfo?.version || "1.0.0"}</p>
            <p>Build: {sysInfo?.build_date || "—"}</p>
          </CardContent>
        </Card>
      </div>
    </div>
  );
}

function SettingField({ label, desc, children }: { label: string; desc: string; children: React.ReactNode }) {
  return (
    <div className="flex items-center justify-between">
      <div>
        <p className="text-sm font-medium text-[#F8FAFC]">{label}</p>
        <p className="text-xs text-[#94A3B8]">{desc}</p>
      </div>
      {children}
    </div>
  );
}

function SysInfoCard({ label, value, icon: Icon, color }: { label: string; value: string; icon: React.ElementType; color: string }) {
  return (
    <div className="rounded-lg border border-[#0B1220] bg-[#0B1220] p-4">
      <div className="flex items-center gap-2 mb-2">
        <Icon className="h-4 w-4" style={{ color }} />
        <span className="text-xs text-[#94A3B8]">{label}</span>
      </div>
      <p className="text-lg font-bold text-[#F8FAFC]" style={{ color }}>{value}</p>
    </div>
  );
}

function DBStatRow({ label, value, color }: { label: string; value: string; color: string }) {
  return (
    <div className="flex items-center justify-between">
      <span className="text-sm text-[#94A3B8]">{label}</span>
      <span className="text-sm font-bold font-mono" style={{ color }}>{value}</span>
    </div>
  );
}
