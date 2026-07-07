import axios from "axios";
import type { DatabaseInfo, ScanResult, UpdateStats } from "@/types";

const api = axios.create({
  baseURL: "/api",
  timeout: 30000,
});

// Database info — API returns JSON directly
export async function fetchDatabaseInfo(): Promise<DatabaseInfo> {
  const { data } = await api.get<DatabaseInfo>("/db/info");
  return data;
}

// Get database stats
export async function getDbStats(): Promise<{ cves: number; kev: number; epss: number }> {
  const info = await fetchDatabaseInfo();
  return { cves: info.cve_count, kev: info.kev_count, epss: info.epss_count };
}

// Run scan
export async function runScan(target: string, ports?: string): Promise<ScanResult> {
  const params = new URLSearchParams({ target });
  if (ports) params.set("ports", ports);
  const { data } = await api.get<ScanResult>(`/scan?${params}`);
  return data;
}

// Trigger update
export async function triggerUpdate(): Promise<{ status: string }> {
  const { data } = await api.post<{ status: string }>("/update");
  return data;
}

// Get update status
export async function getUpdateStatus(): Promise<{ running: boolean; progress: string }> {
  const { data } = await api.get("/update/status");
  return data;
}

export default api;
