"use client";

import { useEffect, useState } from "react";
import Link from "next/link";
import { createClient } from "@/src/lib/supabase/client";
import { API_BASE } from "@/lib/api";
import {
  Package,
  ShieldAlert,
  ShieldCheck,
  FolderOpen,
  Clock,
  ArrowRight,
  CheckCircle2,
  AlertCircle,
  Loader2,
  ChevronRight,
} from "lucide-react";
import { cn } from "@/lib/utils";

/* ─── Types ──────────────────────────────────────────── */
type RecentScan = {
  id: string;
  repo_name: string;
  ecosystem: string;
  status: "done" | "running" | "failed";
  component_count: number;
  critical_cves: number;
  ntia_score: number | null;
  created_at: string;
};

type DashboardStats = {
  total_projects: number;
  total_scans: number;
  total_components: number;
  critical_cves: number;
  high_cves: number;
  medium_cves: number;
  low_cves: number;
  ntia_compliant_scans: number;
  non_compliant_scans: number;
  clean_projects: number;
  recent_scans: RecentScan[];
};

/* ─── Helpers ────────────────────────────────────────── */
function timeAgo(dateStr: string): string {
  const diff = Date.now() - new Date(dateStr).getTime();
  const mins = Math.floor(diff / 60000);
  if (mins < 1) return "just now";
  if (mins < 60) return `${mins}m ago`;
  const hrs = Math.floor(mins / 60);
  if (hrs < 24) return `${hrs}h ago`;
  return `${Math.floor(hrs / 24)}d ago`;
}

function ecosystemColor(eco: string): string {
  const map: Record<string, string> = {
    npm: "bg-yellow-500/15 text-yellow-400 ring-yellow-500/30",
    maven: "bg-red-500/15 text-red-400 ring-red-500/30",
    pip: "bg-blue-500/15 text-blue-400 ring-blue-500/30",
    cargo: "bg-orange-500/15 text-orange-400 ring-orange-500/30",
    go: "bg-cyan-500/15 text-cyan-400 ring-cyan-500/30",
  };
  return map[eco?.toLowerCase()] ?? "bg-slate-500/15 text-slate-400 ring-slate-500/30";
}

/* ─── Sub-components ─────────────────────────────────── */
function StatCard({
  label,
  value,
  icon: Icon,
  accent,
  sub,
}: {
  label: string;
  value: string | number;
  icon: React.ElementType;
  accent?: string;
  sub?: string;
}) {
  return (
    <div className="relative overflow-hidden rounded-xl border border-border/70 bg-card p-6 transition-shadow hover:shadow-md">
      <div className="flex items-start justify-between">
        <div>
          <p className="text-xs font-medium uppercase tracking-wider text-muted-foreground">
            {label}
          </p>
          <p
            className={cn(
              "mt-2 text-4xl font-bold tabular-nums tracking-tight",
              accent ?? "text-foreground"
            )}
          >
            {value}
          </p>
          {sub && (
            <p className="mt-1 text-xs text-muted-foreground">{sub}</p>
          )}
        </div>
        <div
          className={cn(
            "flex h-11 w-11 items-center justify-center rounded-lg",
            accent
              ? accent.includes("red")
                ? "bg-red-500/10"
                : accent.includes("green")
                ? "bg-green-500/10"
                : "bg-primary/10"
              : "bg-primary/10"
          )}
        >
          <Icon
            className={cn(
              "h-5 w-5",
              accent
                ? accent.includes("red")
                  ? "text-red-500"
                  : accent.includes("green")
                  ? "text-green-500"
                  : "text-primary"
                : "text-primary"
            )}
          />
        </div>
      </div>
    </div>
  );
}

function SeverityBar({
  label,
  count,
  maxCount,
  color,
}: {
  label: string;
  count: number;
  maxCount: number;
  color: string;
}) {
  const pct = maxCount === 0 ? 0 : Math.round((count / maxCount) * 100);
  return (
    <div className="flex items-center gap-3">
      <span className="w-16 shrink-0 text-xs font-medium text-muted-foreground">
        {label}
      </span>
      <div className="relative flex-1 h-2.5 rounded-full bg-muted overflow-hidden">
        <div
          className={cn("absolute left-0 top-0 h-full rounded-full transition-all duration-700", color)}
          style={{ width: `${pct}%` }}
        />
      </div>
      <span className="w-8 text-right text-xs font-semibold tabular-nums text-foreground">
        {count}
      </span>
    </div>
  );
}

function StatusDot({ status }: { status: string }) {
  if (status === "done")
    return (
      <span className="flex h-2 w-2 rounded-full bg-emerald-500 ring-2 ring-emerald-500/20" />
    );
  if (status === "running")
    return (
      <span className="flex h-2 w-2 rounded-full bg-amber-400 ring-2 ring-amber-400/20 animate-pulse" />
    );
  return (
    <span className="flex h-2 w-2 rounded-full bg-red-500 ring-2 ring-red-500/20" />
  );
}

/* ─── Main Page ──────────────────────────────────────── */
export default function DashboardPage() {
  const [stats, setStats] = useState<DashboardStats | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let isMounted = true;
    const controller = new AbortController();

    async function load() {
      try {
        const supabase = createClient();
        const {
          data: { session },
        } = await supabase.auth.getSession();

        if (!session?.access_token) {
          if (isMounted) {
            setLoading(false);
            setError("Not authenticated");
          }
          return;
        }

        const res = await fetch(`${API_BASE}/api/dashboard/stats`, {
          headers: { Authorization: `Bearer ${session.access_token}` },
          cache: "no-store",
          signal: controller.signal,
        });

        if (!res.ok) {
          throw new Error(`HTTP ${res.status}: ${res.statusText}`);
        }

        const data = await res.json();
        if (isMounted) {
          setStats(data);
          setError(null);
        }
      } catch (err) {
        if (err instanceof Error && err.name !== "AbortError") {
          console.error("Failed to load dashboard stats:", err);
          if (isMounted) {
            setError(err.message);
          }
        }
      } finally {
        if (isMounted) {
          setLoading(false);
        }
      }
    }

    load();

    return () => {
      isMounted = false;
      controller.abort();
    };
  }, []);

  const s = stats;
  const totalVulns = (s?.critical_cves ?? 0) + (s?.high_cves ?? 0) + (s?.medium_cves ?? 0) + (s?.low_cves ?? 0);
  const maxVuln = Math.max(
    s?.critical_cves ?? 0,
    s?.high_cves ?? 0,
    s?.medium_cves ?? 0,
    s?.low_cves ?? 0,
    1
  );
  const totalDoneScans = (s?.ntia_compliant_scans ?? 0) + (s?.non_compliant_scans ?? 0);
  const compliancePct = totalDoneScans === 0 ? 0 : Math.round(((s?.ntia_compliant_scans ?? 0) / totalDoneScans) * 100);

  return (
    <div className="space-y-8">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold tracking-tight">Dashboard</h1>
          <p className="mt-1 text-sm text-muted-foreground">
            Security and compliance overview for your repositories.
          </p>
        </div>
        <Link
          href="/dashboard/projects/new"
          className="inline-flex items-center gap-2 rounded-lg bg-primary px-4 py-2 text-sm font-medium text-primary-foreground hover:bg-primary/90 transition-colors"
        >
          New Scan
          <ArrowRight className="h-4 w-4" />
        </Link>
      </div>

      {/* Stat Cards */}
      {loading ? (
        <div className="flex h-32 items-center justify-center">
          <Loader2 className="h-6 w-6 animate-spin text-muted-foreground" />
        </div>
      ) : error ? (
        <div className="flex h-32 items-center justify-center rounded-lg border border-red-500/30 bg-red-500/5 p-4">
          <div className="text-center">
            <p className="text-sm font-medium text-red-400">Failed to load dashboard</p>
            <p className="mt-1 text-xs text-red-300">{error}</p>
          </div>
        </div>
      ) : (
        <>
          <div className="grid gap-4 sm:grid-cols-2 xl:grid-cols-4">
            <StatCard
              label="Total Components"
              value={(s?.total_components ?? 0).toLocaleString()}
              icon={Package}
              sub={`across ${s?.total_scans ?? 0} scans`}
            />
            <StatCard
              label="Critical CVEs"
              value={s?.critical_cves ?? 0}
              icon={ShieldAlert}
              accent={(s?.critical_cves ?? 0) > 0 ? "text-red-500" : "text-green-500"}
              sub={(s?.critical_cves ?? 0) > 0 ? `${totalVulns} total vulnerabilities` : "No critical issues"}
            />
            <StatCard
              label="NTIA Compliant"
              value={`${s?.ntia_compliant_scans ?? 0}/${totalDoneScans}`}
              icon={ShieldCheck}
              accent={compliancePct === 100 ? "text-green-500" : compliancePct >= 60 ? "text-amber-500" : "text-red-500"}
              sub={`${compliancePct}% compliance rate`}
            />
            <StatCard
              label="Clean Projects"
              value={s?.clean_projects ?? 0}
              icon={FolderOpen}
              accent={(s?.clean_projects ?? 0) === (s?.total_projects ?? 0) && (s?.total_projects ?? 0) > 0 ? "text-green-500" : "text-foreground"}
              sub={`of ${s?.total_projects ?? 0} total projects`}
            />
          </div>

          {/* Main Content: Two columns */}
          <div className="grid gap-6 lg:grid-cols-5">
            {/* Left — Recent Scans */}
            <div className="lg:col-span-3 rounded-xl border border-border/70 bg-card">
              <div className="flex items-center justify-between border-b border-border/60 px-5 py-4">
                <h2 className="text-sm font-semibold">Recent Scans</h2>
                <Link
                  href="/dashboard/scans"
                  className="inline-flex items-center gap-1 text-xs text-muted-foreground hover:text-foreground transition-colors"
                >
                  View all <ChevronRight className="h-3 w-3" />
                </Link>
              </div>

              {!s?.recent_scans?.length ? (
                <div className="flex flex-col items-center justify-center gap-3 py-16 text-center">
                  <Package className="h-10 w-10 text-muted-foreground/40" />
                  <p className="text-sm text-muted-foreground">No scans yet.</p>
                  <Link
                    href="/dashboard/projects/new"
                    className="text-xs font-medium text-primary hover:underline"
                  >
                    Start your first scan →
                  </Link>
                </div>
              ) : (
                <ul className="divide-y divide-border/50">
                  {s.recent_scans.map((scan) => (
                    <li key={scan.id}>
                      <Link
                        href={`/dashboard/scans/${scan.id}`}
                        className="flex items-center gap-4 px-5 py-3.5 hover:bg-muted/40 transition-colors group"
                      >
                        <StatusDot status={scan.status} />
                        <div className="min-w-0 flex-1">
                          <div className="flex items-center gap-2">
                            <span className="truncate text-sm font-medium text-foreground group-hover:text-primary transition-colors">
                              {scan.repo_name || "Unknown repo"}
                            </span>
                            <span
                              className={cn(
                                "inline-flex items-center rounded px-1.5 py-0.5 text-[10px] font-semibold ring-1 ring-inset",
                                ecosystemColor(scan.ecosystem)
                              )}
                            >
                              {scan.ecosystem || "unknown"}
                            </span>
                          </div>
                          <div className="mt-0.5 flex items-center gap-2 text-[11px] text-muted-foreground">
                            <Clock className="h-3 w-3" />
                            {timeAgo(scan.created_at)}
                            <span>·</span>
                            <span>{scan.component_count.toLocaleString()} components</span>
                            {scan.critical_cves > 0 && (
                              <>
                                <span>·</span>
                                <span className="text-red-500 font-medium">
                                  {scan.critical_cves} critical
                                </span>
                              </>
                            )}
                          </div>
                        </div>
                        <div className="shrink-0 text-right">
                          {scan.ntia_score !== null ? (
                            <span
                              className={cn(
                                "text-xs font-semibold tabular-nums",
                                (scan.ntia_score ?? 0) === 100
                                  ? "text-emerald-500"
                                  : (scan.ntia_score ?? 0) >= 60
                                  ? "text-amber-500"
                                  : "text-red-500"
                              )}
                            >
                              {scan.ntia_score}/100
                            </span>
                          ) : (
                            <span className="text-xs text-muted-foreground">-</span>
                          )}
                          <p className="text-[10px] text-muted-foreground">NTIA</p>
                        </div>
                        <ChevronRight className="h-4 w-4 text-muted-foreground/50 group-hover:text-muted-foreground transition-colors" />
                      </Link>
                    </li>
                  ))}
                </ul>
              )}
            </div>

            {/* Right — Security Overview */}
            <div className="lg:col-span-2 space-y-6">
              <div className="rounded-xl border border-border/70 bg-card p-5">
                <h2 className="mb-4 text-sm font-semibold">Security Overview</h2>
                <div className="space-y-3">
                  <SeverityBar
                    label="Critical"
                    count={s?.critical_cves ?? 0}
                    maxCount={maxVuln}
                    color="bg-red-500"
                  />
                  <SeverityBar
                    label="High"
                    count={s?.high_cves ?? 0}
                    maxCount={maxVuln}
                    color="bg-orange-500"
                  />
                  <SeverityBar
                    label="Medium"
                    count={s?.medium_cves ?? 0}
                    maxCount={maxVuln}
                    color="bg-amber-400"
                  />
                  <SeverityBar
                    label="Low"
                    count={s?.low_cves ?? 0}
                    maxCount={maxVuln}
                    color="bg-blue-400"
                  />
                </div>
                {totalVulns > 0 && (
                  <div className="mt-4 pt-4 border-t border-border/60">
                    <Link
                      href="/dashboard/vulnerabilities"
                      className="inline-flex items-center gap-1 text-xs font-medium text-primary hover:underline"
                    >
                      View all {totalVulns} vulnerabilities <ArrowRight className="h-3 w-3" />
                    </Link>
                  </div>
                )}
              </div>

              {/* Compliance Overview */}
              <div className="rounded-xl border border-border/70 bg-card p-5">
                <h2 className="mb-4 text-sm font-semibold">Compliance Overview</h2>

                {totalDoneScans === 0 ? (
                  <p className="text-xs text-muted-foreground">
                    No completed scans yet.
                  </p>
                ) : compliancePct === 100 ? (
                  <div className="flex items-center gap-2 rounded-lg bg-emerald-500/10 border border-emerald-500/20 px-4 py-3">
                    <CheckCircle2 className="h-5 w-5 shrink-0 text-emerald-500" />
                    <p className="text-sm font-medium text-emerald-400">
                      All projects are NTIA compliant ✓
                    </p>
                  </div>
                ) : (
                  <>
                    <div className="mb-3 flex items-center justify-between text-xs">
                      <span className="text-muted-foreground">
                        {s?.ntia_compliant_scans} of {totalDoneScans} scans compliant
                      </span>
                      <span
                        className={cn(
                          "font-semibold",
                          compliancePct >= 60 ? "text-amber-500" : "text-red-500"
                        )}
                      >
                        {compliancePct}%
                      </span>
                    </div>
                    <div className="h-2 w-full overflow-hidden rounded-full bg-muted">
                      <div
                        className={cn(
                          "h-full rounded-full transition-all duration-700",
                          compliancePct >= 80
                            ? "bg-emerald-500"
                            : compliancePct >= 50
                            ? "bg-amber-500"
                            : "bg-red-500"
                        )}
                        style={{ width: `${compliancePct}%` }}
                      />
                    </div>

                    {(s?.non_compliant_scans ?? 0) > 0 && (
                      <div className="mt-4 rounded-lg border border-amber-500/20 bg-amber-500/5 p-3">
                        <div className="flex items-start gap-2">
                          <AlertCircle className="mt-0.5 h-4 w-4 shrink-0 text-amber-500" />
                          <div>
                            <p className="text-xs font-medium text-amber-400">
                              {s?.non_compliant_scans} scan{(s?.non_compliant_scans ?? 0) > 1 ? "s need" : " needs"} attention
                            </p>
                            <Link
                              href="/dashboard/reports"
                              className="mt-1 inline-flex items-center gap-1 text-xs text-amber-400/80 hover:text-amber-400 hover:underline"
                            >
                              View compliance report <ArrowRight className="h-3 w-3" />
                            </Link>
                          </div>
                        </div>
                      </div>
                    )}
                  </>
                )}
              </div>
            </div>
          </div>
        </>
      )}
    </div>
  );
}
