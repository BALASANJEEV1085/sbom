import Link from "next/link";
import { createClient } from "@/src/lib/supabase/server";
import { listScans } from "@/lib/api";
import { Badge } from "@/components/ui/badge";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";

export default async function ScansListPage() {
  const supabase = await createClient();
  const {
    data: { session },
  } = await supabase.auth.getSession();

  let scans: Awaited<ReturnType<typeof listScans>>["scans"] = [];
  if (session?.access_token) {
    try {
      const res = await listScans(session.access_token);
      scans = res.scans;
    } catch {
      /* ignore */
    }
  }

  return (
    <div className="space-y-6">
      <div className="flex flex-wrap items-center justify-between gap-4">
        <div>
          <h1 className="text-2xl font-semibold tracking-tight">Scans</h1>
          <p className="mt-1 text-sm text-muted-foreground">
            History of dependency resolution runs.
          </p>
        </div>
        <Link
          href="/dashboard/projects/new"
          className="text-sm font-medium text-primary hover:underline"
        >
          New scan
        </Link>
      </div>

      <Card>
        <CardHeader>
          <CardTitle className="text-base">All scans</CardTitle>
        </CardHeader>
        <CardContent>
          {scans.length === 0 ? (
            <p className="text-sm text-muted-foreground">
              No scans yet. Start one from{" "}
              <Link href="/dashboard/projects/new" className="text-primary hover:underline">
                New project
              </Link>
              .
            </p>
          ) : (
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Repository</TableHead>
                  <TableHead>Started</TableHead>
                  <TableHead>Status</TableHead>
                  <TableHead className="text-right">Open</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {scans.map((s) => (
                  <TableRow key={s.id}>
                    <TableCell className="font-medium">
                      {s.project_name || s.github_url || "—"}
                    </TableCell>
                    <TableCell className="text-muted-foreground">
                      {new Date(s.created_at).toLocaleString()}
                    </TableCell>
                    <TableCell>
                      <Badge
                        variant={
                          s.status === "done"
                            ? "default"
                            : s.status === "failed"
                              ? "destructive"
                              : "secondary"
                        }
                      >
                        {s.status}
                      </Badge>
                    </TableCell>
                    <TableCell className="text-right">
                      <Link
                        href={`/dashboard/scans/${s.id}`}
                        className="text-primary hover:underline"
                      >
                        View
                      </Link>
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          )}
        </CardContent>
      </Card>
    </div>
  );
}
