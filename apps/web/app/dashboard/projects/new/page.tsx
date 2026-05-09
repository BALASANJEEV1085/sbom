"use client";

import { Suspense, FormEvent, useEffect, useState } from "react";
import { useSearchParams } from "next/navigation";
import Link from "next/link";
import { Loader2 } from "lucide-react";
import { createClient } from "@/src/lib/supabase/client";
import { ApiError, createProject, getScan, startScan } from "@/lib/api";
import { Button } from "@/components/ui/button";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { Input } from "@/components/ui/input";

export default function NewProjectScanPage() {
  return (
    <Suspense
      fallback={
        <div className="flex justify-center p-12 text-muted-foreground">
          <Loader2 className="h-8 w-8 animate-spin" />
        </div>
      }
    >
      <NewProjectScanForm />
    </Suspense>
  );
}

function NewProjectScanForm() {
  const searchParams = useSearchParams();
  const [githubUrl, setGithubUrl] = useState("");
  const [busy, setBusy] = useState(false);
  const [statusText, setStatusText] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    const url = searchParams.get("url");
    if (url) {
      setGithubUrl(decodeURIComponent(url));
    }
  }, [searchParams]);

  async function onSubmit(e: FormEvent) {
    e.preventDefault();
    setError(null);
    setStatusText(null);
    setBusy(true);

    try {
      const supabase = createClient();
      const {
        data: { session },
      } = await supabase.auth.getSession();
      const token = session?.access_token;
      if (!token) {
        setError("Not signed in.");
        setBusy(false);
        return;
      }

      const existingProject = searchParams.get("project");
      let projectId = existingProject;

      if (!projectId) {
        setStatusText("Creating project…");
        const project = await createProject(token, githubUrl.trim());
        projectId = project.id;
      }

      setStatusText("Starting scan…");
      const started = await startScan(
        token,
        githubUrl.trim(),
        projectId!,
      );

      const scanId = started.scan_id;
      setStatusText("Scan running — resolving dependencies…");

      for (;;) {
        await new Promise((r) => setTimeout(r, 2000));
        const data = await getScan(token, scanId);
        setStatusText(`Status: ${data.scan.status}…`);
        if (data.scan.status === "done" || data.scan.status === "failed") {
          if (data.scan.status === "failed") {
            setError("Scan failed. Check API logs or repository access.");
            setBusy(false);
            return;
          }
          window.location.href = `/dashboard/scans/${scanId}`;
          return;
        }
      }
    } catch (err) {
      const msg =
        err instanceof ApiError
          ? err.body || err.message
          : err instanceof Error
            ? err.message
            : "Something went wrong";
      setError(typeof msg === "string" ? msg : "Request failed");
      setBusy(false);
    }
  }

  return (
    <div className="mx-auto max-w-lg space-y-6">
      <div>
        <h1 className="text-2xl font-semibold tracking-tight">New project</h1>
        <p className="mt-1 text-sm text-muted-foreground">
          Paste a public GitHub repository URL to scan its{" "}
          <code className="rounded bg-muted px-1">package.json</code> tree.
        </p>
      </div>

      <Card>
        <CardHeader>
          <CardTitle className="text-base">Repository</CardTitle>
          <CardDescription>
            Example:{" "}
            <span className="font-mono text-xs">
              https://github.com/expressjs/express
            </span>
          </CardDescription>
        </CardHeader>
        <CardContent>
          <form className="space-y-4" onSubmit={onSubmit}>
            <Input
              required
              type="url"
              placeholder="https://github.com/your-org/your-repo"
              value={githubUrl}
              onChange={(ev) => setGithubUrl(ev.target.value)}
              disabled={busy}
              autoComplete="off"
            />
            <Button type="submit" className="w-full" disabled={busy}>
              {busy ? (
                <>
                  <Loader2 className="mr-2 h-4 w-4 animate-spin" />
                  Working…
                </>
              ) : (
                "Start scan"
              )}
            </Button>
            {statusText ? (
              <p className="flex items-center gap-2 text-sm text-muted-foreground">
                {busy ? (
                  <Loader2 className="h-4 w-4 shrink-0 animate-spin" />
                ) : null}
                {statusText}
              </p>
            ) : null}
            {error ? (
              <p className="text-sm text-destructive whitespace-pre-wrap">
                {error}
              </p>
            ) : null}
          </form>
        </CardContent>
      </Card>

      <p className="text-center text-sm text-muted-foreground">
        <Link href="/dashboard/projects" className="hover:underline">
          Back to projects
        </Link>
      </p>
    </div>
  );
}
