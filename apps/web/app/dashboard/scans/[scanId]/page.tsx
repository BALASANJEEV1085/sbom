"use client";

import Link from "next/link";
import { useParams } from "next/navigation";
import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { ArrowDownAZ, ArrowUpAZ, ChevronDown, Copy, Download, Loader2, Share2, X, CheckCircle2, XCircle, FileText } from "lucide-react";
import { createClient } from "@/src/lib/supabase/client";
import { API_BASE, ApiError, type GetScanResponse, type ScanComponent, getScan } from "@/lib/api";
import { Badge } from "@/components/ui/badge";
import { Button, buttonVariants } from "@/components/ui/button";
import { cn } from "@/lib/utils";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { Collapsible, CollapsibleContent, CollapsibleTrigger } from "@/components/ui/collapsible";

type SortKey = "name" | "version" | "license" | "depth" | "ecosystem";
type SortDir = "asc" | "desc";
type Vulnerability = { component_name: string; component_version: string; cve_id: string; severity: string; summary: string; fixed_version: string; };
type VulnSummary = { critical: number; high: number; medium: number; low: number; };
type VulnResponse = { summary: VulnSummary; vulnerabilities: Vulnerability[]; };

function Stat({ label, value }: { label: string; value: number }) {
  return (
    <Card className="border-border/80">
      <CardHeader className="pb-2 pt-4">
        <CardDescription className="text-xs font-medium uppercase tracking-wide">{label}</CardDescription>
        <CardTitle className="text-2xl tabular-nums">{value}</CardTitle>
      </CardHeader>
    </Card>
  );
}

// ── Share modal ──────────────────────────────────────────────────────────────
function ShareModal({ scanId, open, onClose }: { scanId: string; open: boolean; onClose: () => void }) {
  const [label, setLabel] = useState("");
  const [days, setDays] = useState("90");
  const [loading, setLoading] = useState(false);
  const [shareUrl, setShareUrl] = useState<string | null>(null);
  const [copied, setCopied] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  const [sbomId, setSbomId] = useState<string | null>(null);

  useEffect(() => {
    if (!open) { setShareUrl(null); setSbomId(null); setErr(null); setLabel(""); setDays("90"); setCopied(false); }
  }, [open]);

  const generate = async () => {
    setLoading(true); setErr(null);
    try {
      const supabase = createClient();
      const { data: { session } } = await supabase.auth.getSession();
      const token = session?.access_token;
      if (!token) throw new Error("Not signed in");

      let sid = sbomId;
      if (!sid) {
        const genRes = await fetch(`${API_BASE}/api/scans/${scanId}/sbom`, {
          method: "POST", headers: { "Content-Type": "application/json", Authorization: `Bearer ${token}` },
          body: JSON.stringify({ format: "cyclonedx" }),
        });
        if (!genRes.ok) throw new Error(`SBOM generation failed: ${genRes.status}`);
        const genData = await genRes.json();
        sid = genData.sbom_id as string;
        setSbomId(sid);
      }

      const shareRes = await fetch(`${API_BASE}/api/sboms/${sid}/share`, {
        method: "POST", headers: { "Content-Type": "application/json", Authorization: `Bearer ${token}` },
        body: JSON.stringify({ label, expires_in_days: parseInt(days) }),
      });
      if (!shareRes.ok) throw new Error(`Share creation failed: ${shareRes.status}`);
      const shareData = await shareRes.json();
      setShareUrl(shareData.share_url as string);
    } catch (e) {
      setErr(e instanceof Error ? e.message : "Unknown error");
    } finally {
      setLoading(false);
    }
  };

  const copy = () => { if (shareUrl) { navigator.clipboard.writeText(shareUrl); setCopied(true); setTimeout(() => setCopied(false), 2000); } };

  if (!open) return null;
  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/70 backdrop-blur-sm p-4">
      <div className="relative w-full max-w-md rounded-xl border border-border bg-card shadow-2xl p-6 space-y-4">
        <button onClick={onClose} className="absolute top-4 right-4 text-muted-foreground hover:text-foreground"><X className="h-4 w-4" /></button>
        <div>
          <h2 className="text-lg font-semibold">Share SBOM</h2>
          <p className="text-sm text-muted-foreground mt-1">This link works without login — share it with any auditor.</p>
        </div>
        {!shareUrl ? (
          <div className="space-y-3">
            <div>
              <label className="text-xs font-medium text-muted-foreground uppercase tracking-wide">Label (optional)</label>
              <Input className="mt-1" placeholder="e.g. For DRDO Audit Q1 2026" value={label} onChange={e => setLabel(e.target.value)} />
            </div>
            <div>
              <label className="text-xs font-medium text-muted-foreground uppercase tracking-wide">Expires in</label>
              <select value={days} onChange={e => setDays(e.target.value)}
                className="mt-1 w-full rounded-md border border-input bg-background px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-ring">
                <option value="30">30 days</option>
                <option value="60">60 days</option>
                <option value="90">90 days</option>
                <option value="180">180 days</option>
              </select>
            </div>
            {err && <p className="text-xs text-destructive">{err}</p>}
            <Button className="w-full" onClick={generate} disabled={loading}>
              {loading ? <><Loader2 className="h-4 w-4 mr-2 animate-spin" />Generating…</> : "Generate Share Link"}
            </Button>
          </div>
        ) : (
          <div className="space-y-3">
            <p className="text-sm text-green-500 font-medium">✓ Share link created</p>
            <div className="flex gap-2">
              <Input readOnly value={shareUrl} className="font-mono text-xs" />
              <Button variant="outline" size="icon" onClick={copy} title="Copy">
                {copied ? <span className="text-xs text-green-500">✓</span> : <Copy className="h-4 w-4" />}
              </Button>
            </div>
            <p className="text-xs text-muted-foreground">Link expires in {days} days. Anyone with this link can view the compliance report.</p>
          </div>
        )}
      </div>
    </div>
  );
}

// ── Export dropdown ──────────────────────────────────────────────────────────
function ExportDropdown({ scanId, disabled }: { scanId: string; disabled: boolean }) {
  const [open, setOpen] = useState(false);
  const [loading, setLoading] = useState<string | null>(null);
  const [toast, setToast] = useState<string | null>(null);
  const ref = useRef<HTMLDivElement>(null);

  useEffect(() => {
    const handler = (e: MouseEvent) => { if (ref.current && !ref.current.contains(e.target as Node)) setOpen(false); };
    document.addEventListener("mousedown", handler);
    return () => document.removeEventListener("mousedown", handler);
  }, []);

  const exportSBOM = async (format: "cyclonedx" | "spdx") => {
    setOpen(false); setLoading(format);
    try {
      const supabase = createClient();
      const { data: { session } } = await supabase.auth.getSession();
      const token = session?.access_token;
      if (!token) throw new Error("Not signed in");
      const res = await fetch(`${API_BASE}/api/scans/${scanId}/sbom`, {
        method: "POST", headers: { "Content-Type": "application/json", Authorization: `Bearer ${token}` },
        body: JSON.stringify({ format }),
      });
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      const data = await res.json();
      const ext = format === "cyclonedx" ? "json" : "spdx";
      const mimeType = format === "cyclonedx" ? "application/json" : "text/plain";
      const fileName = data.file_name || `sbom-${scanId.slice(0, 8)}.${ext}`;

      const binary = atob(data.file_data as string);
      const bytes = new Uint8Array(binary.length);
      for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
      const blob = new Blob([bytes], { type: mimeType });
      const blobUrl = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = blobUrl; a.download = fileName;
      document.body.appendChild(a); a.click();
      document.body.removeChild(a);
      setTimeout(() => URL.revokeObjectURL(blobUrl), 5000);
      setToast("SBOM downloaded successfully");
      setTimeout(() => setToast(null), 3000);
    } catch (e) {
      setToast(e instanceof Error ? e.message : "Export failed");
      setTimeout(() => setToast(null), 4000);
    } finally { setLoading(null); }
  };

  const downloadPDF = async () => {
    setOpen(false); setLoading("pdf");
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
      setToast("PDF report downloaded successfully");
      setTimeout(() => setToast(null), 3000);
    } catch (e) {
      console.error(e);
      setToast("PDF Download failed");
      setTimeout(() => setToast(null), 4000);
    } finally { setLoading(null); }
  };

  return (
    <>
      {toast && (
        <div className="fixed bottom-6 right-6 z-50 rounded-lg border border-border bg-card px-4 py-3 text-sm shadow-xl">
          {toast}
        </div>
      )}
      <div ref={ref} className="relative">
        <Button onClick={() => setOpen(o => !o)} disabled={disabled || !!loading} className="gap-1">
          {loading ? <><Loader2 className="h-4 w-4 animate-spin" />Generating…</> : <><Download className="h-4 w-4" />Export<ChevronDown className="h-3 w-3" /></>}
        </Button>
        {open && (
          <div className="absolute right-0 top-full z-20 mt-1 w-64 rounded-lg border border-border bg-popover shadow-xl">
            <button onClick={() => exportSBOM("cyclonedx")}
              className="flex w-full items-center gap-2 px-4 py-2.5 text-sm hover:bg-muted transition-colors rounded-t-lg">
              <Download className="h-4 w-4 text-muted-foreground" />
              Download CycloneDX JSON (.json)
            </button>
            <button onClick={() => exportSBOM("spdx")}
              className="flex w-full items-center gap-2 px-4 py-2.5 text-sm hover:bg-muted transition-colors border-t border-border">
              <Download className="h-4 w-4 text-muted-foreground" />
              Download SPDX (.spdx)
            </button>
            <button onClick={downloadPDF}
              className="flex w-full items-center gap-2 px-4 py-2.5 text-sm hover:bg-muted transition-colors rounded-b-lg border-t border-border">
              <FileText className="h-4 w-4 text-muted-foreground" />
              Download PDF Report
            </button>
          </div>
        )}
      </div>
    </>
  );
}

// ── Main page ────────────────────────────────────────────────────────────────
export default function ScanDetailPage() {
  const params = useParams();
  const scanId = typeof params.scanId === "string" ? params.scanId : "";
  const [data, setData] = useState<GetScanResponse | null>(null);
  const [vulnData, setVulnData] = useState<VulnResponse | null>(null);
  const [compData, setCompData] = useState<any | null>(null);
  const [loadError, setLoadError] = useState<string | null>(null);
  const [search, setSearch] = useState("");
  const [sortKey, setSortKey] = useState<SortKey>("name");
  const [sortDir, setSortDir] = useState<SortDir>("asc");
  const [activeTab, setActiveTab] = useState<"vulnerabilities" | "dependencies">("vulnerabilities");
  const [shareOpen, setShareOpen] = useState(false);

  const load = useCallback(async () => {
    const supabase = createClient();
    const { data: { session } } = await supabase.auth.getSession();
    const token = session?.access_token;
    if (!token) { setLoadError("Not signed in."); return null; }
    
    const scanRes = await getScan(token, scanId);
    let vulns: VulnResponse | null = null;
    let compliance: any = null;
    
    try {
      const [vRes, cRes] = await Promise.all([
        fetch(`${API_BASE}/api/scans/${scanId}/vulnerabilities`, { headers: { Authorization: `Bearer ${token}` } }),
        fetch(`${API_BASE}/api/scans/${scanId}/compliance`, { headers: { Authorization: `Bearer ${token}` } })
      ]);
      if (vRes.ok) vulns = await vRes.json();
      if (cRes.ok) compliance = await cRes.json();
    } catch (e) { console.error("Failed to fetch auxiliary data", e); }
    
    return { scanRes, vulns, compliance };
  }, [scanId]);

  useEffect(() => {
    if (!scanId) return;
    let timer: ReturnType<typeof setTimeout> | undefined;
    const loop = async () => {
      try {
        const next = await load();
        if (!next) return;
        setData(next.scanRes); 
        setVulnData(next.vulns); 
        setCompData(next.compliance);
        setLoadError(null);
        if (next.scanRes.scan.status === "running") timer = setTimeout(loop, 2000);
      } catch (e) {
        const msg = e instanceof ApiError ? e.body || e.message : e instanceof Error ? e.message : "Failed to load scan";
        setLoadError(typeof msg === "string" ? msg : "Error");
      }
    };
    void loop();
    return () => { if (timer) clearTimeout(timer); };
  }, [scanId, load]);

  const filteredSorted = useMemo(() => {
    if (!data?.components) return [];
    const q = search.trim().toLowerCase();
    let rows = data.components.filter(c => q ? c.name.toLowerCase().includes(q) : true);
    rows = [...rows].sort((a, b) => {
      const av = a[sortKey], bv = b[sortKey];
      const cmp = typeof av === "number" && typeof bv === "number" ? av - bv : String(av).localeCompare(String(bv), undefined, { sensitivity: "base" });
      return sortDir === "asc" ? cmp : -cmp;
    });
    return rows;
  }, [data, search, sortKey, sortDir]);

  const stats = useMemo(() => {
    if (!data?.components) return { total: 0, direct: 0, transitive: 0, licenses: 0 };
    const comps = data.components;
    const direct = comps.filter(c => c.depth === 0).length;
    const licenses = new Set(comps.map(c => c.license?.trim()).filter(Boolean)).size;
    return { total: comps.length, direct, transitive: Math.max(0, comps.length - direct), licenses };
  }, [data]);

  function toggleSort(key: SortKey) {
    if (sortKey === key) setSortDir(d => d === "asc" ? "desc" : "asc");
    else { setSortKey(key); setSortDir("asc"); }
  }

  function SortIcon({ column }: { column: SortKey }) {
    if (sortKey !== column) return null;
    return sortDir === "asc" ? <ArrowUpAZ className="ml-1 inline h-3.5 w-3.5 opacity-60" /> : <ArrowDownAZ className="ml-1 inline h-3.5 w-3.5 opacity-60" />;
  }

  const downloadPDF = async () => {
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

  if (!scanId) return <p className="text-sm text-muted-foreground">Missing scan id.</p>;
  if (loadError && !data) return (
    <div className="space-y-4">
      <p className="text-destructive text-sm whitespace-pre-wrap">{loadError}</p>
      <Link href="/dashboard/scans" className={cn(buttonVariants({ variant: "outline" }))}>Back to scans</Link>
    </div>
  );
  if (!data) return (
    <div className="flex items-center gap-2 text-muted-foreground">
      <Loader2 className="h-5 w-5 animate-spin" />Loading scan…
    </div>
  );

  const title = data.project?.display_title ?? "Scan results";
  const totalVulns = vulnData ? vulnData.summary.critical + vulnData.summary.high + vulnData.summary.medium + vulnData.summary.low : 0;
  const scanDone = data.scan.status === "done";

  const sevColor: Record<string, string> = {
    CRITICAL: "bg-red-600 text-white",
    HIGH: "bg-orange-500 text-white",
    MEDIUM: "bg-yellow-500 text-black",
    LOW: "bg-blue-500 text-white",
  };

  return (
    <>
      <ShareModal scanId={scanId} open={shareOpen} onClose={() => setShareOpen(false)} />
      <div className="space-y-6">
        {/* Header */}
        <div className="flex flex-wrap items-start justify-between gap-4">
          <div>
            <p className="text-sm text-muted-foreground">
              <Link href="/dashboard/scans" className="hover:underline">Scans</Link>
              <span className="mx-1.5">/</span>
              <span className="font-mono text-xs">{scanId.slice(0, 8)}…</span>
            </p>
            <h1 className="mt-1 text-2xl font-semibold tracking-tight">Scan results — {title}</h1>
            <div className="mt-2 flex flex-wrap items-center gap-2">
              <Badge variant={data.scan.status === "done" ? "default" : data.scan.status === "failed" ? "destructive" : "secondary"}>
                {data.scan.status === "running" ? <span className="inline-flex items-center gap-1.5"><Loader2 className="h-3 w-3 animate-spin" />running</span> : data.scan.status}
              </Badge>
              <span className="text-xs text-muted-foreground">Started {new Date(data.scan.created_at).toLocaleString()}</span>
            </div>
          </div>
          <div className="flex items-center gap-2 ">
            <Button variant="outline" onClick={downloadPDF} disabled={!scanDone} className="gap-1.5 cursor-pointer">
              <FileText className="h-4 w-4 " />Download PDF Report
            </Button>
            <Button variant="outline" onClick={() => setShareOpen(true)} disabled={!scanDone} className="gap-1.5 cursor-pointer">
              <Share2 className="h-4 w-4" />Share with auditor
            </Button>
            <ExportDropdown scanId={scanId} disabled={!scanDone} />
          </div>
        </div>

        {/* Stats */}
        <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-5">
          <Stat label="Total components" value={stats.total} />
          <Stat label="Direct deps" value={stats.direct} />
          <Stat label="Transitive deps" value={stats.transitive} />
          <Stat label="Licenses found" value={stats.licenses} />
          <Card className="border-border/80">
            <CardHeader className="pb-2 pt-4">
              <CardDescription className="text-xs font-medium uppercase tracking-wide">Critical CVEs</CardDescription>
              <CardTitle className={cn("text-2xl tabular-nums", vulnData?.summary.critical && vulnData.summary.critical > 0 ? "text-red-600 dark:text-red-500" : "text-green-600 dark:text-green-500")}>
                {vulnData ? vulnData.summary.critical : 0}
              </CardTitle>
            </CardHeader>
          </Card>
        </div>

        {/* Compliance Card */}
        {compData && scanDone && (
          <Card className="border-border/80">
            <CardHeader className="pb-3">
              <CardTitle className="text-lg">Compliance Assessment</CardTitle>
            </CardHeader>
            <CardContent>
              <div className="flex flex-col md:flex-row gap-8 items-center md:items-start mb-2">
                <div className="flex-shrink-0 relative">
                  <svg className="w-32 h-32 transform -rotate-90">
                    <circle cx="64" cy="64" r="56" stroke="currentColor" strokeWidth="12" fill="transparent" className="text-muted" />
                    <circle cx="64" cy="64" r="56" stroke="currentColor" strokeWidth="12" fill="transparent" 
                      strokeDasharray={351.8} strokeDashoffset={351.8 - (351.8 * (Number(compData.score) || 0)) / 100}
                      className={cn("transition-all duration-1000", (compData.score || 0) === 100 ? "text-green-500" : (compData.score || 0) >= 60 ? "text-orange-500" : "text-red-500")} />
                  </svg>
                  <div className="absolute inset-0 flex items-center justify-center">
                    <span className="text-2xl font-bold">{compData.score || 0}/100</span>
                  </div>
                </div>
                
                <div className="flex-1 space-y-4 w-full">
                  <div className="flex flex-wrap gap-2">
                    <Badge variant={compData.compliant ? "default" : "destructive"} className="px-3 py-1 text-sm">
                      NTIA EO14028: {compData.compliant ? "COMPLIANT" : "NON-COMPLIANT"}
                    </Badge>
                    <Badge variant={compData.eu_cra_compliant ? "default" : "secondary"} className="px-3 py-1 text-sm bg-blue-600 hover:bg-blue-700 text-white">
                      EU CRA: {compData.eu_cra_compliant ? "COMPLIANT" : "NON-COMPLIANT"}
                    </Badge>
                  </div>
                  
                  <Collapsible className="w-full border rounded-md">
                    <CollapsibleTrigger className="flex w-full items-center justify-between px-4 py-3 text-sm font-medium hover:bg-muted/50 transition-colors">
                      View NTIA Minimum Elements Checklist
                      <ChevronDown className="h-4 w-4" />
                    </CollapsibleTrigger>
                    <CollapsibleContent className="border-t divide-y">
                      {compData.elements?.map((el: any, i: number) => (
                        <div key={i} className="px-4 py-3 flex items-start gap-3 text-sm">
                          {el.passed ? <CheckCircle2 className="h-5 w-5 text-green-500 mt-0.5 shrink-0" /> : <XCircle className="h-5 w-5 text-red-500 mt-0.5 shrink-0" />}
                          <div className="flex-1 space-y-2">
                            <div className="flex items-center justify-between">
                              <span className="font-medium">{el.name}</span>
                              <span className="text-muted-foreground">{el.coverage}% coverage</span>
                            </div>
                            <div className="w-full h-1.5 bg-muted rounded-full overflow-hidden">
                              <div className={cn("h-full", el.passed ? "bg-green-500" : "bg-red-500")} style={{ width: `${el.coverage}%` }} />
                            </div>
                            <p className="text-muted-foreground text-xs">{el.detail}</p>
                          </div>
                        </div>
                      ))}
                    </CollapsibleContent>
                  </Collapsible>
                </div>
              </div>

              {!compData.compliant && compData.recommendations?.length > 0 && (
                <div className="bg-yellow-500/10 border border-yellow-500/20 rounded-md p-4 mt-6">
                  <h4 className="text-sm font-semibold text-yellow-600 dark:text-yellow-500 mb-2">Recommendations to achieve compliance:</h4>
                  <ul className="list-disc pl-5 space-y-1">
                    {compData.recommendations.map((rec: string, i: number) => (
                      <li key={i} className="text-sm text-yellow-700 dark:text-yellow-400/90">{rec}</li>
                    ))}
                  </ul>
                </div>
              )}
            </CardContent>
          </Card>
        )}

        {/* Vuln summary banner */}
        {vulnData && scanDone && (
          <div className="rounded-lg border bg-card text-card-foreground shadow-sm p-4 flex items-center justify-between">
            {totalVulns === 0 ? (
              <span className="text-sm font-medium text-green-600 dark:text-green-500">✓ No vulnerabilities found — this project is clean</span>
            ) : (
              <div className="flex gap-4 text-sm font-medium">
                <span className="text-red-600 dark:text-red-500">Critical — {vulnData.summary.critical}</span>
                <span className="text-orange-500">High — {vulnData.summary.high}</span>
                <span className="text-yellow-500">Medium — {vulnData.summary.medium}</span>
                <span className="text-blue-400">Low — {vulnData.summary.low}</span>
              </div>
            )}
          </div>
        )}

        {/* Tabs */}
        <div className="flex gap-1 border-b border-border">
          {(["vulnerabilities", "dependencies"] as const).map(tab => (
            <button key={tab} onClick={() => setActiveTab(tab)}
              className={cn("px-4 py-2 text-sm font-medium capitalize transition-colors border-b-2 -mb-px", activeTab === tab ? "border-primary text-foreground" : "border-transparent text-muted-foreground hover:text-foreground")}>
              {tab}{tab === "vulnerabilities" && vulnData ? ` (${totalVulns})` : tab === "dependencies" && data ? ` (${data.total})` : ""}
            </button>
          ))}
        </div>

        {/* Vulnerabilities tab */}
        {activeTab === "vulnerabilities" && (
          <Card>
            <CardHeader><CardTitle className="text-base">Vulnerabilities</CardTitle></CardHeader>
            <CardContent className="p-0">
              {!vulnData ? (
                <div className="flex items-center gap-2 p-6 text-muted-foreground"><Loader2 className="h-4 w-4 animate-spin" />Loading…</div>
              ) : vulnData.vulnerabilities.length === 0 ? (
                <p className="p-6 text-sm text-muted-foreground">No vulnerabilities found.</p>
              ) : (
                <div className="overflow-auto max-h-[60vh]">
                  <Table>
                    <TableHeader>
                      <TableRow>
                        <TableHead>CVE</TableHead>
                        <TableHead>Severity</TableHead>
                        <TableHead>Package</TableHead>
                        <TableHead>Fixed in</TableHead>
                        <TableHead>Summary</TableHead>
                      </TableRow>
                    </TableHeader>
                    <TableBody>
                      {vulnData.vulnerabilities.map((v, i) => (
                        <TableRow key={i}>
                          <TableCell className="font-mono text-xs whitespace-nowrap">
                            <a href={`https://nvd.nist.gov/vuln/detail/${v.cve_id}`} target="_blank" rel="noopener noreferrer" className="hover:underline text-blue-400">{v.cve_id}</a>
                          </TableCell>
                          <TableCell>
                            <span className={cn("inline-flex items-center rounded-full px-2 py-0.5 text-xs font-semibold", sevColor[v.severity.toUpperCase()] ?? "bg-muted text-foreground")}>
                              {v.severity}
                            </span>
                          </TableCell>
                          <TableCell className="font-mono text-xs">{v.component_name}@{v.component_version}</TableCell>
                          <TableCell className="font-mono text-xs text-green-400">{v.fixed_version || "—"}</TableCell>
                          <TableCell className="text-xs max-w-xs truncate">{v.summary}</TableCell>
                        </TableRow>
                      ))}
                    </TableBody>
                  </Table>
                </div>
              )}
            </CardContent>
          </Card>
        )}

        {/* Dependencies tab */}
        {activeTab === "dependencies" && (
          <Card>
            <CardHeader className="flex flex-row items-center justify-between gap-4">
              <CardTitle className="text-base">Dependencies ({data.total})</CardTitle>
              <Input placeholder="Filter by name…" value={search} onChange={e => setSearch(e.target.value)} className="h-8 w-56 text-sm" />
            </CardHeader>
            <CardContent className="p-0">
              <div className="overflow-auto max-h-[60vh]">
                <Table>
                  <TableHeader>
                    <TableRow>
                      {(["name", "version", "license", "ecosystem", "depth"] as SortKey[]).map(col => (
                        <TableHead key={col} className="cursor-pointer select-none whitespace-nowrap" onClick={() => toggleSort(col)}>
                          {col.charAt(0).toUpperCase() + col.slice(1)}<SortIcon column={col} />
                        </TableHead>
                      ))}
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {filteredSorted.length === 0 ? (
                      <TableRow><TableCell colSpan={5} className="py-8 text-center text-muted-foreground">No results</TableCell></TableRow>
                    ) : filteredSorted.map((c: ScanComponent) => (
                      <TableRow key={c.id}>
                        <TableCell className="font-mono text-xs font-medium">{c.name}</TableCell>
                        <TableCell className="font-mono text-xs">{c.version}</TableCell>
                        <TableCell className="text-xs">{c.license || "—"}</TableCell>
                        <TableCell className="text-xs">{c.ecosystem}</TableCell>
                        <TableCell className="text-xs">{c.depth}</TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              </div>
            </CardContent>
          </Card>
        )}
      </div>
    </>
  );
}
