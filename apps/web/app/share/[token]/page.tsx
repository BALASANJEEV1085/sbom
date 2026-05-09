"use client";

import { useEffect, useState } from "react";
import { useParams } from "next/navigation";
import { API_BASE } from "@/lib/api";
import { CheckCircle2, XCircle, Loader2, ShieldCheck } from "lucide-react";
import { cn } from "@/lib/utils";

type ComplianceReport = {
  label: string;
  repo_name: string;
  generated_at: string;
  sha256: string;
  format: string;
  spec_version: string;
  component_count: number;
  vulnerability_summary: { critical: number; high: number; medium: number; low: number };
  compliance: {
    ntia_minimum_elements: boolean;
    has_supplier_name: boolean;
    has_component_names: boolean;
    has_versions: boolean;
    has_unique_ids: boolean;
    has_dependency_relationships: boolean;
    has_author: boolean;
    has_timestamp: boolean;
  };
  components: { name: string; version: string; license: string; ecosystem: string; depth: number; parent_name: string }[];
  vulnerabilities: { component_name: string; component_version: string; cve_id: string; severity: string; summary: string; fixed_version: string }[];
};

const NTIA_LABELS: { key: keyof ComplianceReport["compliance"]; label: string }[] = [
  { key: "ntia_minimum_elements", label: "NTIA Minimum Elements Met" },
  { key: "has_supplier_name", label: "Supplier Name" },
  { key: "has_component_names", label: "Component Names" },
  { key: "has_versions", label: "Version Information" },
  { key: "has_unique_ids", label: "Unique Identifiers (PURL)" },
  { key: "has_dependency_relationships", label: "Dependency Relationships" },
  { key: "has_author", label: "Author of SBOM Data" },
  { key: "has_timestamp", label: "Timestamp" },
];

const SEV_STYLE: Record<string, string> = {
  CRITICAL: "bg-red-600/15 text-red-400 border border-red-600/30",
  HIGH: "bg-orange-500/15 text-orange-400 border border-orange-500/30",
  MEDIUM: "bg-yellow-500/15 text-yellow-400 border border-yellow-500/30",
  LOW: "bg-blue-500/15 text-blue-400 border border-blue-500/30",
};

export default function ShareViewPage() {
  const params = useParams();
  const token = typeof params.token === "string" ? params.token : "";
  const [report, setReport] = useState<ComplianceReport | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [expired, setExpired] = useState(false);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    if (!token) return;
    (async () => {
      try {
        const res = await fetch(`${API_BASE}/api/share/${token}`);
        if (res.status === 410) { setExpired(true); return; }
        if (!res.ok) { setError(`Error ${res.status}`); return; }
        setReport(await res.json());
      } catch (e) {
        setError(e instanceof Error ? e.message : "Failed to load report");
      } finally { setLoading(false); }
    })();
  }, [token]);

  if (loading) return (
    <div className="min-h-screen bg-[#0a0a0f] flex items-center justify-center">
      <div className="flex items-center gap-3 text-zinc-400"><Loader2 className="h-5 w-5 animate-spin" />Loading compliance report…</div>
    </div>
  );

  if (expired) return (
    <div className="min-h-screen bg-[#0a0a0f] flex flex-col items-center justify-center gap-4">
      <ShieldCheck className="h-12 w-12 text-zinc-600" />
      <h1 className="text-2xl font-bold text-white">This link has expired</h1>
      <p className="text-zinc-400 text-sm">The SBOM share link you followed is no longer valid.</p>
      <a href="https://sbom.io" className="text-indigo-400 hover:underline text-sm">SBOM.io — Software Bill of Materials Platform</a>
    </div>
  );

  if (error || !report) return (
    <div className="min-h-screen bg-[#0a0a0f] flex flex-col items-center justify-center gap-4">
      <h1 className="text-xl font-bold text-white">Share link not found</h1>
      <p className="text-zinc-400 text-sm">{error ?? "This link may be invalid."}</p>
    </div>
  );

  const vs = report.vulnerability_summary;
  const totalVulns = vs.critical + vs.high + vs.medium + vs.low;

  return (
    <div className="min-h-screen bg-[#0a0a0f] text-zinc-100 font-sans">
      {/* Nav bar */}
      <header className="border-b border-zinc-800 px-6 py-4 flex items-center gap-3">
        <ShieldCheck className="h-6 w-6 text-indigo-400" />
        <span className="font-bold text-lg tracking-tight text-white">SBOM.io</span>
        <span className="ml-auto text-xs text-zinc-500">Read-only compliance report • No account required</span>
      </header>

      <main className="mx-auto max-w-5xl px-4 py-10 space-y-10">
        {/* Title */}
        <div className="space-y-2">
          <div className="flex flex-wrap items-center gap-2">
            <span className="rounded-full bg-indigo-500/15 border border-indigo-500/30 text-indigo-400 text-xs font-semibold px-3 py-1">
              {report.format === "cyclonedx" ? "CycloneDX" : "SPDX"} {report.spec_version}
            </span>
            {report.label && (
              <span className="rounded-full bg-zinc-800 border border-zinc-700 text-zinc-300 text-xs px-3 py-1">{report.label}</span>
            )}
          </div>
          <h1 className="text-3xl font-bold text-white">SBOM Compliance Report</h1>
          <p className="text-lg text-zinc-400">{report.repo_name}</p>
        </div>

        {/* Meta */}
        <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
          {[
            { label: "Generated", value: new Date(report.generated_at).toLocaleDateString() },
            { label: "Components", value: report.component_count.toLocaleString() },
            { label: "Format", value: report.format === "cyclonedx" ? "CycloneDX 1.5" : "SPDX 2.3" },
            { label: "SHA-256", value: report.sha256.slice(0, 16) + "…" },
          ].map(m => (
            <div key={m.label} className="rounded-xl border border-zinc-800 bg-zinc-900/50 p-4">
              <p className="text-xs text-zinc-500 uppercase tracking-wide mb-1">{m.label}</p>
              <p className="font-mono text-sm font-semibold text-zinc-100 truncate">{m.value}</p>
            </div>
          ))}
        </div>

        {/* NTIA Compliance */}
        <section>
          <h2 className="text-lg font-semibold mb-4 flex items-center gap-2">
            <ShieldCheck className={cn("h-5 w-5", report.compliance.ntia_minimum_elements ? "text-green-400" : "text-red-400")} />
            NTIA Minimum Elements
            <span className={cn("text-sm font-normal", report.compliance.ntia_minimum_elements ? "text-green-400" : "text-red-400")}>
              {report.compliance.ntia_minimum_elements ? "— Compliant" : "— Non-compliant"}
            </span>
          </h2>
          <div className="grid sm:grid-cols-2 gap-2">
            {NTIA_LABELS.map(({ key, label }) => {
              const ok = report.compliance[key];
              return (
                <div key={key} className={cn("flex items-center gap-3 rounded-lg border px-4 py-3 text-sm", ok ? "border-green-800/50 bg-green-900/10" : "border-red-800/50 bg-red-900/10")}>
                  {ok ? <CheckCircle2 className="h-4 w-4 text-green-400 shrink-0" /> : <XCircle className="h-4 w-4 text-red-400 shrink-0" />}
                  <span className={ok ? "text-zinc-200" : "text-zinc-400"}>{label}</span>
                </div>
              );
            })}
          </div>
        </section>

        {/* Vulnerability summary */}
        <section>
          <h2 className="text-lg font-semibold mb-4">Vulnerabilities</h2>
          <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
            {[
              { label: "Critical", count: vs.critical, cls: "border-red-600/40 bg-red-600/10 text-red-400" },
              { label: "High", count: vs.high, cls: "border-orange-500/40 bg-orange-500/10 text-orange-400" },
              { label: "Medium", count: vs.medium, cls: "border-yellow-500/40 bg-yellow-500/10 text-yellow-400" },
              { label: "Low", count: vs.low, cls: "border-blue-500/40 bg-blue-500/10 text-blue-400" },
            ].map(b => (
              <div key={b.label} className={cn("rounded-xl border p-5 text-center", b.cls)}>
                <p className="text-3xl font-bold tabular-nums">{b.count}</p>
                <p className="text-xs font-medium mt-1 uppercase tracking-wide opacity-80">{b.label}</p>
              </div>
            ))}
          </div>
          {totalVulns === 0 && <p className="mt-4 text-sm text-green-400 font-medium">✓ No vulnerabilities detected</p>}
        </section>

        {/* Vulnerabilities table */}
        {report.vulnerabilities.length > 0 && (
          <section>
            <h2 className="text-lg font-semibold mb-4">Vulnerability Details</h2>
            <div className="rounded-xl border border-zinc-800 overflow-auto max-h-80">
              <table className="w-full text-sm">
                <thead className="bg-zinc-900 border-b border-zinc-800 sticky top-0">
                  <tr>
                    {["CVE", "Severity", "Package", "Fixed In", "Summary"].map(h => (
                      <th key={h} className="text-left px-4 py-3 text-xs font-semibold text-zinc-400 uppercase tracking-wide">{h}</th>
                    ))}
                  </tr>
                </thead>
                <tbody>
                  {report.vulnerabilities.map((v, i) => (
                    <tr key={i} className="border-b border-zinc-800/50 hover:bg-zinc-900/40 transition-colors">
                      <td className="px-4 py-2.5 font-mono text-xs text-indigo-400 whitespace-nowrap">
                        <a href={`https://nvd.nist.gov/vuln/detail/${v.cve_id}`} target="_blank" rel="noopener noreferrer" className="hover:underline">{v.cve_id}</a>
                      </td>
                      <td className="px-4 py-2.5">
                        <span className={cn("rounded-full px-2 py-0.5 text-xs font-semibold", SEV_STYLE[v.severity.toUpperCase()] ?? "bg-zinc-700 text-zinc-200")}>{v.severity}</span>
                      </td>
                      <td className="px-4 py-2.5 font-mono text-xs text-zinc-300 whitespace-nowrap">{v.component_name}@{v.component_version}</td>
                      <td className="px-4 py-2.5 font-mono text-xs text-green-400">{v.fixed_version || "—"}</td>
                      <td className="px-4 py-2.5 text-xs text-zinc-400 max-w-xs truncate">{v.summary}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </section>
        )}

        {/* Components table */}
        <section>
          <h2 className="text-lg font-semibold mb-4">Components ({report.component_count.toLocaleString()})</h2>
          <div className="rounded-xl border border-zinc-800 overflow-auto max-h-96">
            <table className="w-full text-sm">
              <thead className="bg-zinc-900 border-b border-zinc-800 sticky top-0">
                <tr>
                  {["Name", "Version", "License", "Ecosystem"].map(h => (
                    <th key={h} className="text-left px-4 py-3 text-xs font-semibold text-zinc-400 uppercase tracking-wide">{h}</th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {report.components.map((c, i) => (
                  <tr key={i} className="border-b border-zinc-800/50 hover:bg-zinc-900/40 transition-colors">
                    <td className="px-4 py-2.5 font-mono text-xs font-medium text-zinc-100">{c.name}</td>
                    <td className="px-4 py-2.5 font-mono text-xs text-zinc-300">{c.version}</td>
                    <td className="px-4 py-2.5 text-xs text-zinc-400">{c.license || "—"}</td>
                    <td className="px-4 py-2.5 text-xs text-zinc-400">{c.ecosystem}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </section>
      </main>

      {/* Footer */}
      <footer className="border-t border-zinc-800 px-6 py-5 text-center text-xs text-zinc-600 mt-10">
        Verified by <span className="text-indigo-400 font-semibold">SBOM.io</span> &nbsp;·&nbsp; Not logged in — read only &nbsp;·&nbsp; <a href="https://sbom.io" className="hover:text-zinc-400 transition-colors">sbom.io</a>
      </footer>
    </div>
  );
}
