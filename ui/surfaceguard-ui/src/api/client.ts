import axios from "axios";
import type {
  DatabaseInfo,
  ScanResult,
  UpdateStats,
  CredentialProfile,
  ValidationResult,
  AssessmentResult,
  AssetDetail,
  ScanProgress,
  EASMScan,
  EASMAsset,
  EASMFinding,
} from "@/types";

const api = axios.create({
  baseURL: "/api",
  timeout: 30000,
});

// Extended timeout API instance for long-running assessments
const apiLong = axios.create({
  baseURL: "/api",
  timeout: 600000, // 10 minutes
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

// ==========================================================================
// Authenticated Assessment API
// ==========================================================================

// Credential Profiles
export async function listCredentialProfiles(): Promise<CredentialProfile[]> {
  const { data } = await api.get<CredentialProfile[]>("/credentials/profiles");
  return data;
}

export async function createCredentialProfile(profile: {
  name: string;
  protocol: string;
  host: string;
  port: number;
  username: string;
  auth_method: string;
  password?: string;
  private_key?: string;
  passphrase?: string;
  community?: string;
}): Promise<{ id: number }> {
  const { data } = await api.post("/credentials/profiles", profile);
  return data;
}

export async function deleteCredentialProfile(id: number): Promise<void> {
  await api.delete(`/credentials/profile`, { params: { id } });
}

// Credential Validation
export async function validateCredentials(profileId: number): Promise<ValidationResult> {
  const { data } = await api.post<ValidationResult>("/credentials/validate", { profile_id: profileId });
  return data;
}

// Assessment Scan — uses extended timeout for long-running operations.
export async function runAssessmentScan(profileId: number): Promise<AssessmentResult> {
  const { data } = await apiLong.get<AssessmentResult>("/assessment/scan", { params: { profile_id: profileId } });
  return data;
}

// Assessment Scan via SSE — returns progress callbacks for live status updates.
export function runAssessmentScanSSE(
  profileId: number,
  onProgress: (progress: ScanProgress) => void,
  onResult: (result: AssessmentResult) => void,
  onError: (error: string) => void,
): () => void {
  const url = `/api/assessment/scan/progress?profile_id=${profileId}`;
  const source = new EventSource(url);

  source.addEventListener("progress", (event: MessageEvent) => {
    try {
      const data: ScanProgress = JSON.parse(event.data);
      onProgress(data);
    } catch { /* ignore parse errors */ }
  });

  source.addEventListener("result", (event: MessageEvent) => {
    try {
      const data: AssessmentResult = JSON.parse(event.data);
      onResult(data);
      source.close();
    } catch { /* ignore */ }
  });

  source.addEventListener("error", (event: MessageEvent) => {
    try {
      const data = JSON.parse(event.data);
      onError(data.error || "Assessment failed");
    } catch {
      onError("Assessment failed");
    }
    source.close();
  });

  source.onerror = () => {
    // EventSource auto-reconnects, but if it keeps failing we give up.
    onError("Connection lost during assessment");
    source.close();
  };

  // Return a cleanup function.
  return () => source.close();
}

// Assessment History
export async function getAssessmentHistory(limit: number = 20): Promise<AssessmentResult[]> {
  const { data } = await api.get<AssessmentResult[]>("/assessment/history", { params: { limit } });
  return data;
}

// Asset Inventory
export async function listAssets(): Promise<AssetDetail[]> {
  const { data } = await api.get<AssetDetail[]>("/assets");
  return data;
}

export async function getAssetDetail(id: number): Promise<AssetDetail> {
  const { data } = await api.get<AssetDetail>("/asset", { params: { id } });
  return data;
}

// ==========================================================================
// EASM API
// ==========================================================================

export async function listEASMScans(): Promise<EASMScan[]> {
  const { data } = await api.get<EASMScan[]>("/easm/scans");
  return data;
}

export async function createEASMScan(req: any): Promise<any> {
  const { data } = await api.post("/easm/scan", req);
  return data;
}

export async function getEASMAssets(scanId: number): Promise<EASMAsset[]> {
  const { data } = await api.get<EASMAsset[]>("/easm/assets", { params: { scan_id: scanId } });
  return data;
}

export async function getEASMFindings(scanId: number): Promise<EASMFinding[]> {
  const { data } = await api.get<EASMFinding[]>("/easm/findings", { params: { scan_id: scanId } });
  return data;
}

export default api;
