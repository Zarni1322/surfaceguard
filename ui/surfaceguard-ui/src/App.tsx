import { BrowserRouter, Routes, Route, Navigate } from "react-router-dom";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { Toaster } from "sonner";
import MainLayout from "@/layouts/MainLayout";
import DashboardPage from "@/pages/dashboard/DashboardPage";
import HostDiscoveryPage from "@/pages/host-discovery/HostDiscoveryPage";
import CVEDiscoveryPage from "@/pages/cve-discovery/CVEDiscoveryPage";
import AssetsPage from "@/pages/assets/AssetsPage";
import ScanHistoryPage from "@/pages/scan-history/ScanHistoryPage";
import ReportsPage from "@/pages/reports/ReportsPage";
import UpdatesPage from "@/pages/updates/UpdatesPage";
import DatabasePage from "@/pages/database/DatabasePage";
import SettingsPage from "@/pages/settings/SettingsPage";

const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      staleTime: 10000,
      retry: 2,
    },
  },
});

export default function App() {
  return (
    <QueryClientProvider client={queryClient}>
      <BrowserRouter>
        <Routes>
          <Route element={<MainLayout />}>
            <Route path="/" element={<DashboardPage />} />
            <Route path="/host-discovery" element={<HostDiscoveryPage />} />
            <Route path="/cve-discovery" element={<CVEDiscoveryPage />} />
            <Route path="/assets" element={<AssetsPage />} />
            <Route path="/scan-history" element={<ScanHistoryPage />} />
            <Route path="/reports" element={<ReportsPage />} />
            <Route path="/updates" element={<UpdatesPage />} />
            <Route path="/database" element={<DatabasePage />} />
            <Route path="/settings" element={<SettingsPage />} />
            <Route path="*" element={<Navigate to="/" replace />} />
          </Route>
        </Routes>
      </BrowserRouter>
      <Toaster position="bottom-right" theme="dark" />
    </QueryClientProvider>
  );
}
