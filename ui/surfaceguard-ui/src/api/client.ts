import axios from "axios";
import type {
  DatabaseInfo,
  ScanResult,
  UpdateStats,
  CredentialProfile,
  ValidationResult,
  AssessmentResult,
  AssetDetail,
} from "@/types";

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

// Assessment Scan
export async function runAssessmentScan(profileId: number): Promise<AssessmentResult> {
  const { data } = await api.get<AssessmentResult>("/assessment/scan", { params: { profile_id: profileId } });
  return data;
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

export default api;
