"use client";

import { useCallback, useEffect, useState } from "react";
import { useParams } from "next/navigation";
import Link from "next/link";
import { Copy, ExternalLink, Loader2, Trash2 } from "lucide-react";
import { createClient } from "@/src/lib/supabase/client";
import { API_BASE } from "@/lib/api";
import { Button, buttonVariants } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { cn } from "@/lib/utils";
import {
  Table, TableBody, TableCell, TableHead,
  TableHeader, TableRow,
} from "@/components/ui/table";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";

type ShareLink = {
  id: string;
  share_url: string;
  label: string;
  expires_at: string;
  view_count: number;
  created_at: string;
  expired: boolean;
};

export default function SharesPage() {
  const params = useParams();
  const scanId = typeof params.scanId === "string" ? params.scanId : "";

  const [sbomId, setSbomId] = useState<string | null>(null);
  const [links, setLinks] = useState<ShareLink[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [copied, setCopied] = useState<string | null>(null);
  const [revoking, setRevoking] = useState<string | null>(null);
  const [toast, setToast] = useState<string | null>(null);

  const getToken = async () => {
    const supabase = createClient();
    const { data: { session } } = await supabase.auth.getSession();
    return session?.access_token ?? null;
  };

  // First fetch the latest sbom_id for this scan, then list its shares
  const loadShares = useCallback(async () => {
    setLoading(true); setError(null);
    try {
      const token = await getToken();
      if (!token) { setError("Not signed in"); return; }

      // Get the most recent sbom for this scan
      // We do this by generating if needed or fetching existing
      // Try listing sboms via the shares endpoint — we need an sbomId first.
      // Fetch scan info to confirm it exists, then get sbomId from local state or generate
      const scanRes = await fetch(`${API_BASE}/api/scans/${scanId}`, {
        headers: { Authorization: `Bearer ${token}` },
      });
      if (!scanRes.ok) { setError(`Scan not found (${scanRes.status})`); return; }

      // If we don't have an sbomId yet, try to generate one
      // (idempotent — just get the sbom_id from a new generation call)
      let sid = sbomId;
      if (!sid) {
        const genRes = await fetch(`${API_BASE}/api/scans/${scanId}/sbom`, {
          method: "POST",
          headers: { "Content-Type": "application/json", Authorization: `Bearer ${token}` },
          body: JSON.stringify({ format: "cyclonedx" }),
        });
        if (!genRes.ok) { setError(`Could not load SBOM (${genRes.status})`); return; }
        const genData = await genRes.json();
        sid = genData.sbom_id as string;
        setSbomId(sid);
      }

      const sharesRes = await fetch(`${API_BASE}/api/sboms/${sid}/shares`, {
        headers: { Authorization: `Bearer ${token}` },
      });
      if (!sharesRes.ok) { setError(`Failed to load shares (${sharesRes.status})`); return; }
      const sharesData = await sharesRes.json();
      setLinks(sharesData.links ?? []);
    } catch (e) {
      setError(e instanceof Error ? e.message : "Unknown error");
    } finally { setLoading(false); }
  }, [scanId, sbomId]);

  useEffect(() => { if (scanId) void loadShares(); }, [scanId]);

  const copy = (url: string, id: string) => {
    navigator.clipboard.writeText(url);
    setCopied(id);
    setTimeout(() => setCopied(null), 2000);
  };

  const revoke = async (linkId: string) => {
    const token = await getToken();
    if (!token || !sbomId) return;
    setRevoking(linkId);
    try {
      const res = await fetch(`${API_BASE}/api/sboms/${sbomId}/shares/${linkId}`, {
        method: "DELETE",
        headers: { Authorization: `Bearer ${token}` },
      });
      if (res.ok || res.status === 404) {
        setLinks(prev => prev.filter(l => l.id !== linkId));
        setToast("Share link revoked");
      } else {
        setToast(`Revoke failed (${res.status})`);
      }
    } catch {
      setToast("Revoke failed");
    } finally {
      setRevoking(null);
      setTimeout(() => setToast(null), 3000);
    }
  };

  return (
    <div className="space-y-6">
      {/* Toast */}
      {toast && (
        <div className="fixed bottom-6 right-6 z-50 rounded-lg border border-border bg-card px-4 py-3 text-sm shadow-xl">
          {toast}
        </div>
      )}

      {/* Header */}
      <div className="flex flex-wrap items-center justify-between gap-4">
        <div>
          <p className="text-sm text-muted-foreground">
            <Link href="/dashboard/scans" className="hover:underline">Scans</Link>
            <span className="mx-1.5">/</span>
            <Link href={`/dashboard/scans/${scanId}`} className="hover:underline font-mono text-xs">{scanId.slice(0, 8)}…</Link>
            <span className="mx-1.5">/</span>
            <span>Shared Links</span>
          </p>
          <h1 className="mt-1 text-2xl font-semibold tracking-tight">SBOM Share Links</h1>
          <p className="text-sm text-muted-foreground mt-1">
            Manage secure public links for auditors and clients.
          </p>
        </div>
        <div className="flex gap-2">
          <Link href={`/dashboard/scans/${scanId}`} className={cn(buttonVariants({ variant: "outline" }))}>
            ← Back to scan
          </Link>
          <Button onClick={() => { setSbomId(null); void loadShares(); }} disabled={loading}>
            {loading ? <Loader2 className="h-4 w-4 animate-spin" /> : "Refresh"}
          </Button>
        </div>
      </div>

      {/* Content */}
      <Card>
        <CardHeader>
          <CardTitle className="text-base flex items-center justify-between">
            Active Links
            <Badge variant="secondary">{links.length} total</Badge>
          </CardTitle>
        </CardHeader>
        <CardContent className="p-0">
          {loading ? (
            <div className="flex items-center gap-2 p-6 text-muted-foreground">
              <Loader2 className="h-4 w-4 animate-spin" />
              Loading share links…
            </div>
          ) : error ? (
            <p className="p-6 text-sm text-destructive">{error}</p>
          ) : links.length === 0 ? (
            <div className="p-8 text-center space-y-2">
              <p className="text-muted-foreground text-sm">No share links yet.</p>
              <p className="text-xs text-muted-foreground">
                Go back to the scan page and click <strong>Share with auditor</strong> to create one.
              </p>
            </div>
          ) : (
            <div className="overflow-auto">
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>Label</TableHead>
                    <TableHead>Created</TableHead>
                    <TableHead>Expires</TableHead>
                    <TableHead>Views</TableHead>
                    <TableHead>Status</TableHead>
                    <TableHead>Link</TableHead>
                    <TableHead className="text-right">Actions</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {links.map(link => (
                    <TableRow key={link.id} className={link.expired ? "opacity-50" : ""}>
                      <TableCell className="font-medium text-sm max-w-[160px] truncate">
                        {link.label || <span className="text-muted-foreground italic">No label</span>}
                      </TableCell>
                      <TableCell className="text-xs text-muted-foreground whitespace-nowrap">
                        {new Date(link.created_at).toLocaleDateString()}
                      </TableCell>
                      <TableCell className="text-xs whitespace-nowrap">
                        <span className={link.expired ? "text-destructive" : "text-muted-foreground"}>
                          {new Date(link.expires_at).toLocaleDateString()}
                        </span>
                      </TableCell>
                      <TableCell className="text-sm tabular-nums">{link.view_count}</TableCell>
                      <TableCell>
                        <Badge variant={link.expired ? "destructive" : "default"} className="text-xs">
                          {link.expired ? "Expired" : "Active"}
                        </Badge>
                      </TableCell>
                      <TableCell>
                        <div className="flex items-center gap-1.5">
                          <button
                            onClick={() => copy(link.share_url, link.id)}
                            className="flex items-center gap-1 text-xs text-muted-foreground hover:text-foreground transition-colors"
                            title="Copy link"
                          >
                            {copied === link.id
                              ? <span className="text-green-500 text-xs">✓ Copied</span>
                              : <><Copy className="h-3.5 w-3.5" /><span className="font-mono">{link.share_url.replace("https://sbom.io/share/", "…/")}</span></>
                            }
                          </button>
                          <a
                            href={link.share_url}
                            target="_blank"
                            rel="noopener noreferrer"
                            className="text-muted-foreground hover:text-foreground transition-colors"
                            title="Open link"
                          >
                            <ExternalLink className="h-3.5 w-3.5" />
                          </a>
                        </div>
                      </TableCell>
                      <TableCell className="text-right">
                        <Button
                          variant="ghost"
                          size="sm"
                          className="h-7 w-7 p-0 text-muted-foreground hover:text-destructive hover:bg-destructive/10"
                          onClick={() => revoke(link.id)}
                          disabled={revoking === link.id}
                          title="Revoke link"
                        >
                          {revoking === link.id
                            ? <Loader2 className="h-3.5 w-3.5 animate-spin" />
                            : <Trash2 className="h-3.5 w-3.5" />
                          }
                        </Button>
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </div>
          )}
        </CardContent>
      </Card>

      {/* Info box */}
      <div className="rounded-lg border border-border bg-muted/30 p-4 text-sm text-muted-foreground space-y-1">
        <p className="font-medium text-foreground">About share links</p>
        <p>Share links let auditors, clients, and government agencies view a full SBOM compliance report without needing an account.</p>
        <p>Revoking a link immediately invalidates it — anyone who follows the old URL will see a 404 error.</p>
      </div>
    </div>
  );
}
