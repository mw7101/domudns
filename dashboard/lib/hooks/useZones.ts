"use client";
import { zones, Zone } from "@/lib/api";
import { useApiRequest, ApiRequestState } from "./useApiRequest";

export function useZones(): ApiRequestState<Zone[]> {
  return useApiRequest<Zone[]>(() => zones.list().then((r) => r.data), []);
}
