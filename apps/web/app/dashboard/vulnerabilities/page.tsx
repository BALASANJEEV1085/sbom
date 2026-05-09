"use client";

import { useCallback, useEffect, useMemo, useState } from "react";
import { Loader2, ShieldAlert, ShieldCheck } from "lucide-react";
import { createClient } from "@/src/lib/supabase/client";
import { API_BASE } from "@/lib/api";
import { Badge } from "@/components/ui/badge";
import { cn } from "@/lib/utils";
import {
  Card,
  CardContent,
} from "@/components/ui/card";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";

type Vulnerability = {
  component_name: string;
  component_version: string;
  cve_id: string;
  severity: string;
  summary: string;
  fixed_version: string;
  scan_id: string;
  project_name: string;
};

type VulnSummary = {
  critical: number;
  high: number;
  medium: number;
  low: number;
};

type VulnResponse = {
  summary: VulnSummary;
  vulnerabilities: Vulnerability[];
};

export default function VulnerabilitiesPage() {
  const [data, setData] = useState<VulnResponse | null>(null);
  const [loading, setLoading] = useState(true);
  const [filter, setFilter] = useState("ALL");

  const load = useCallback(async () => {
    const supabase = createClient();
    const {
      data: { session },
    } = await supabase.auth.getSession();
    const token = session?.access_token;
    if (!token) {
      setLoading(false);
      return;
    }

    try {
      const res = await fetch(`${API_BASE}/api/vulnerabilities`, {
        headers: { Authorization: `Bearer ${token}` },
      });
      if (res.ok) {
        const json = await res.json();
        setData(json);
      }
    } catch (e) {
      console.error("Failed to load vulnerabilities", e);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    void load();
  }, [load]);

  const filteredVulns = useMemo(() => {
    if (!data) return [];
    if (filter === "ALL") return data.vulnerabilities;
    return data.vulnerabilities.filter((v) => v.severity === filter);
  }, [data, filter]);

  if (loading) {
    return (
      <div className="flex items-center gap-2 text-muted-foreground">
        <Loader2 className="h-5 w-5 animate-spin" />
        Loading vulnerabilities…
      </div>
    );
  }

  if (!data || data.vulnerabilities.length === 0) {
    return (
      <div className="space-y-6">
        <div>
          <h1 className="text-2xl font-semibold tracking-tight">Vulnerabilities</h1>
          <p className="text-sm text-muted-foreground">
            All detected CVEs across your projects
          </p>
        </div>
        <Card className="flex flex-col items-center justify-center p-12 text-center border-dashed">
          <div className="rounded-full bg-green-500/10 p-4 mb-4">
            <ShieldCheck className="h-12 w-12 text-green-600 dark:text-green-500" />
          </div>
          <h2 className="text-xl font-semibold">All clear</h2>
          <p className="text-muted-foreground mt-2 max-w-sm">
            No vulnerabilities detected across any of your scanned projects. Great job keeping your dependencies up to date!
          </p>
        </Card>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      <div className="flex flex-col sm:flex-row sm:items-end justify-between gap-4">
        <div>
          <h1 className="text-2xl font-semibold tracking-tight">Vulnerabilities</h1>
          <p className="text-sm text-muted-foreground">
            All detected CVEs across your projects
          </p>
        </div>
        <div className="w-full sm:max-w-xs">
          <Select value={filter} onValueChange={(v) => setFilter(v ?? "ALL")}>
            <SelectTrigger>
              <SelectValue placeholder="Filter by severity" />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="ALL">All Severities</SelectItem>
              <SelectItem value="CRITICAL">Critical</SelectItem>
              <SelectItem value="HIGH">High</SelectItem>
              <SelectItem value="MEDIUM">Medium</SelectItem>
              <SelectItem value="LOW">Low</SelectItem>
            </SelectContent>
          </Select>
        </div>
      </div>

      <div className="flex gap-4 text-sm font-medium bg-card border rounded-lg p-4 shadow-sm items-center">
        <ShieldAlert className="h-5 w-5 text-muted-foreground mr-2" />
        <span className="text-red-600 dark:text-red-500">
           Critical - {data.summary.critical}
        </span>
        <span className="text-orange-500">
           High - {data.summary.high}
        </span>
        <span className="text-yellow-500">
           Medium - {data.summary.medium}
        </span>
        <span className="text-green-600 dark:text-green-500">
           Low - {data.summary.low}
        </span>
      </div>

      <Card>
        <CardContent className="p-0">
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead className="pl-4">Project</TableHead>
                <TableHead>Package</TableHead>
                <TableHead>Version</TableHead>
                <TableHead>CVE ID</TableHead>
                <TableHead>Severity</TableHead>
                <TableHead>Found On</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {filteredVulns.length === 0 ? (
                <TableRow>
                  <TableCell colSpan={6} className="h-24 text-center text-muted-foreground">
                    No vulnerabilities found for this severity.
                  </TableCell>
                </TableRow>
              ) : (
                filteredVulns.map((v, i) => (
                  <TableRow key={i}>
                    <TableCell className="pl-4 font-medium">{v.project_name}</TableCell>
                    <TableCell>{v.component_name}</TableCell>
                    <TableCell className="font-mono text-xs">{v.component_version}</TableCell>
                    <TableCell className="font-mono text-xs">{v.cve_id}</TableCell>
                    <TableCell>
                      <Badge
                        variant="outline"
                        className={cn(
                          v.severity === "CRITICAL"
                            ? "border-red-500 text-red-500"
                            : v.severity === "HIGH"
                              ? "border-orange-500 text-orange-500"
                              : v.severity === "MEDIUM"
                                ? "border-yellow-500 text-yellow-500"
                                : "border-green-500 text-green-500"
                        )}
                      >
                        {v.severity}
                      </Badge>
                    </TableCell>
                    <TableCell className="font-mono text-xs text-muted-foreground">
                      {v.scan_id.slice(0, 8)}…
                    </TableCell>
                  </TableRow>
                ))
              )}
            </TableBody>
          </Table>
        </CardContent>
      </Card>
    </div>
  );
}
