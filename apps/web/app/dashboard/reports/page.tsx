"use client";

import Link from "next/link";
import { useEffect, useState } from "react";
import { createClient } from "@/src/lib/supabase/client";
import { API_BASE, type ScanListItem } from "@/lib/api";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { Button, buttonVariants } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Loader2, FileText, Share2, Eye } from "lucide-react";
import { cn } from "@/lib/utils";

type ReportData = ScanListItem & {
  components?: number;
  ntia_score?: number;
  ntia_compliant?: boolean;
  eu_cra_compliant?: boolean;
  cves?: number;
  ecosystem?: string;
  loaded?: boolean;
};

export default function ReportsPage() {
  const [reports, setReports] = useState<ReportData[]>([]);
  const [filter, setFilter] = useState<"all" | "compliant" | "non_compliant">("all");
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    async function load() {
      try {
        const supabase = createClient();
        const { data: { session } } = await supabase.auth.getSession();
        if (!session?.access_token) return;

        const res = await fetch(`${API_BASE}/api/scans`, {
          headers: { Authorization: `Bearer ${session.access_token}` },
        });
        if (!res.ok) return;
        const data = await res.json();
        const scans: ReportData[] = data.scans || [];
        setReports(scans);
        setLoading(false);

        // Fetch details for each scan
        for (let i = 0; i < scans.length; i++) {
          const scan = scans[i];
          if (scan.status !== "done") continue;

          Promise.all([
            fetch(`${API_BASE}/api/scans/${scan.id}`, { headers: { Authorization: `Bearer ${session.access_token}` } }),
            fetch(`${API_BASE}/api/scans/${scan.id}/compliance`, { headers: { Authorization: `Bearer ${session.access_token}` } }),
            fetch(`${API_BASE}/api/scans/${scan.id}/vulnerabilities`, { headers: { Authorization: `Bearer ${session.access_token}` } })
          ]).then(async ([scanRes, compRes, vulnRes]) => {
            let components = 0, ecosystem = "Unknown";
            if (scanRes.ok) {
              const scanData = await scanRes.json();
              components = scanData.total || 0;
              if (scanData.components && scanData.components.length > 0) {
                ecosystem = scanData.components[0].ecosystem;
              }
            }

            let ntia_score = 0, ntia_compliant = false, eu_cra_compliant = false;
            if (compRes.ok) {
              const compData = await compRes.json();
              ntia_score = compData.score;
              ntia_compliant = compData.compliant;
              eu_cra_compliant = compData.eu_cra_compliant;
            }

            let cves = 0;
            if (vulnRes.ok) {
              const vulnData = await vulnRes.json();
              cves = (vulnData.summary?.critical || 0) + (vulnData.summary?.high || 0) + (vulnData.summary?.medium || 0) + (vulnData.summary?.low || 0);
            }

            setReports(prev => prev.map(p => 
              p.id === scan.id ? { ...p, components, ecosystem, ntia_score, ntia_compliant, eu_cra_compliant, cves, loaded: true } : p
            ));
          }).catch(console.error);
        }
      } catch (e) {
        console.error(e);
        setLoading(false);
      }
    }
    load();
  }, []);

  const downloadPDF = async (scanId: string) => {
    try {
      const supabase = createClient();
      const { data: { session } } = await supabase.auth.getSession();
      if (!session?.access_token) return;

      const res = await fetch(`${API_BASE}/api/scans/${scanId}/report/pdf`, {
        headers: { Authorization: `Bearer ${session.access_token}` },
      });
      if (!res.ok) throw new Error("Failed to download PDF");

      const blob = await res.blob();
      const url = window.URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.style.display = "none";
      a.href = url;
      a.download = `sbom-report-${scanId.slice(0, 8)}.pdf`;
      document.body.appendChild(a);
      a.click();
      window.URL.revokeObjectURL(url);
    } catch (e) {
      console.error(e);
    }
  };

  const filtered = reports.filter(r => {
    if (filter === "all") return true;
    if (filter === "compliant") return r.ntia_compliant;
    if (filter === "non_compliant") return r.loaded && !r.ntia_compliant;
    return true;
  });

  return (
    <div className="space-y-6 max-w-7xl mx-auto py-8">
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4">
        <div>
          <h1 className="text-3xl font-bold tracking-tight">Reports</h1>
          <p className="text-muted-foreground mt-1">Compliance assessments and vulnerability summaries for all scans.</p>
        </div>
        <div className="flex bg-muted rounded-md p-1">
          <button onClick={() => setFilter("all")} className={cn("px-3 py-1 text-sm font-medium rounded-sm transition-colors", filter === "all" ? "bg-background shadow-sm text-foreground" : "text-muted-foreground hover:text-foreground")}>All</button>
          <button onClick={() => setFilter("compliant")} className={cn("px-3 py-1 text-sm font-medium rounded-sm transition-colors", filter === "compliant" ? "bg-background shadow-sm text-foreground" : "text-muted-foreground hover:text-foreground")}>Compliant</button>
          <button onClick={() => setFilter("non_compliant")} className={cn("px-3 py-1 text-sm font-medium rounded-sm transition-colors", filter === "non_compliant" ? "bg-background shadow-sm text-foreground" : "text-muted-foreground hover:text-foreground")}>Non-Compliant</button>
        </div>
      </div>

      <div className="rounded-md border">
        <Table>
          <TableHeader>
            <TableRow>
              <TableHead>Project</TableHead>
              <TableHead>Scan Date</TableHead>
              <TableHead>Ecosystem</TableHead>
              <TableHead className="text-center">Components</TableHead>
              <TableHead className="text-center">NTIA Score</TableHead>
              <TableHead className="text-center">EU CRA</TableHead>
              <TableHead className="text-center">CVEs</TableHead>
              <TableHead className="text-right">Actions</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {loading ? (
              <TableRow>
                <TableCell colSpan={8} className="h-24 text-center">
                  <Loader2 className="mx-auto h-5 w-5 animate-spin text-muted-foreground" />
                </TableCell>
              </TableRow>
            ) : filtered.length === 0 ? (
              <TableRow>
                <TableCell colSpan={8} className="h-24 text-center text-muted-foreground">
                  No scans yet — scan a repository to generate reports.
                </TableCell>
              </TableRow>
            ) : (
              filtered.map((report) => (
                <TableRow key={report.id}>
                  <TableCell>
                    <div className="font-medium">{report.project_name || "Unknown"}</div>
                    <div className="text-xs text-muted-foreground">{report.id.slice(0, 8)}</div>
                  </TableCell>
                  <TableCell className="text-xs">{new Date(report.created_at).toLocaleString()}</TableCell>
                  <TableCell className="text-xs">{report.loaded ? report.ecosystem : <Loader2 className="h-3 w-3 animate-spin" />}</TableCell>
                  <TableCell className="text-center text-xs tabular-nums">{report.loaded ? report.components : "-"}</TableCell>
                  <TableCell className="text-center">
                    {report.loaded ? (
                      <Badge variant={report.ntia_compliant ? "default" : "destructive"}>
                        {report.ntia_score}/100
                      </Badge>
                    ) : "-"}
                  </TableCell>
                  <TableCell className="text-center">
                    {report.loaded ? (
                      <Badge variant={report.eu_cra_compliant ? "default" : "secondary"}>
                        {report.eu_cra_compliant ? "PASS" : "FAIL"}
                      </Badge>
                    ) : "-"}
                  </TableCell>
                  <TableCell className="text-center text-xs font-mono">{report.loaded ? report.cves : "-"}</TableCell>
                  <TableCell className="text-right space-x-2">
                    <Link href={`/dashboard/scans/${report.id}`} className={cn(buttonVariants({ variant: "ghost", size: "icon" }))} title="View Scan">
                      <Eye className="h-4 w-4" />
                    </Link>
                    <Button variant="ghost" size="icon" disabled={!report.loaded} onClick={() => downloadPDF(report.id)} title="Download PDF Report">
                      <FileText className="h-4 w-4" />
                    </Button>
                    <Link href={`/dashboard/scans/${report.id}?share=1`} className={cn(buttonVariants({ variant: "ghost", size: "icon" }))} title="Share">
                      <Share2 className="h-4 w-4" />
                    </Link>
                  </TableCell>
                </TableRow>
              ))
            )}
          </TableBody>
        </Table>
      </div>
    </div>
  );
}
