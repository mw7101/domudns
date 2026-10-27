"use client";
import { useState } from "react";
import { zones, DnsRecord } from "@/lib/api";
import { useApiRequest } from "./useApiRequest";

export interface UseRecordsState {
  records: DnsRecord[] | null;
  loading: boolean;
  error: string | null;
  page: number;
  setPage: (n: number) => void;
  refetch: () => void;
}

export function useRecords(domain: string, view?: string): UseRecordsState {
  const [page, setPage] = useState(1);
  const state = useApiRequest<DnsRecord[]>(
    () => {
      const fetch = view ? zones.getView(domain, view) : zones.get(domain);
      return fetch.then((r) => r.data.records ?? []);
    },
    [domain, view, page]
  );
  return { records: state.data, loading: state.loading, error: state.error, refetch: state.refetch, page, setPage };
}
