import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { fetchDatabaseInfo, getDbStats, triggerUpdate, getUpdateStatus } from "@/api/client";

export function useDbInfo() {
  return useQuery({
    queryKey: ["db-info"],
    queryFn: fetchDatabaseInfo,
    refetchInterval: 30000,
  });
}

export function useDbStats() {
  return useQuery({
    queryKey: ["db-stats"],
    queryFn: getDbStats,
    refetchInterval: 15000,
  });
}

export function useUpdateStatus() {
  return useQuery({
    queryKey: ["update-status"],
    queryFn: getUpdateStatus,
    refetchInterval: 5000,
  });
}

export function useTriggerUpdate() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: triggerUpdate,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["db-info"] });
      queryClient.invalidateQueries({ queryKey: ["db-stats"] });
    },
  });
}
