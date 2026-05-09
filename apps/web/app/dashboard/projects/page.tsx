import Link from "next/link";
import { FolderKanban } from "lucide-react";
import { createClient } from "@/src/lib/supabase/server";
import { listProjects } from "@/lib/api";
import { buttonVariants } from "@/components/ui/button";
import { cn } from "@/lib/utils";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";

export default async function ProjectsPage() {
  const supabase = await createClient();
  const {
    data: { session },
  } = await supabase.auth.getSession();

  let projects: Awaited<ReturnType<typeof listProjects>>["projects"] = [];
  if (session?.access_token) {
    try {
      const res = await listProjects(session.access_token);
      projects = res.projects;
    } catch {
      /* ignore */
    }
  }

  return (
    <div className="space-y-6">
      <div className="flex flex-wrap items-center justify-between gap-4">
        <div>
          <h1 className="text-2xl font-semibold tracking-tight">Projects</h1>
          <p className="mt-1 text-sm text-muted-foreground">
            Repositories you scan for SBOM components.
          </p>
        </div>
        <Link
          href="/dashboard/projects/new"
          className={cn(buttonVariants())}
        >
          New project
        </Link>
      </div>

      {projects.length === 0 ? (
        <Card className="border-dashed">
          <CardHeader>
            <CardTitle className="text-base">No projects yet</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="flex flex-col items-center justify-center rounded-lg border border-dashed py-12 text-center">
              <FolderKanban className="mb-3 h-10 w-10 text-muted-foreground" />
              <p className="text-sm font-medium">No projects connected</p>
              <p className="mt-1 max-w-sm text-sm text-muted-foreground">
                Add a public GitHub repository to resolve dependencies end to
                end.
              </p>
              <Link
                href="/dashboard/projects/new"
                className={cn(buttonVariants(), "mt-6")}
              >
                New project
              </Link>
            </div>
          </CardContent>
        </Card>
      ) : (
        <Card>
          <CardHeader>
            <CardTitle className="text-base">Your projects</CardTitle>
          </CardHeader>
          <CardContent>
            <ul className="divide-y">
              {projects.map((p) => (
                <li
                  key={p.id}
                  className="flex flex-wrap items-center justify-between gap-2 py-3 first:pt-0"
                >
                  <div>
                    <p className="font-medium">{p.name}</p>
                    <p className="text-sm text-muted-foreground">{p.github_url}</p>
                  </div>
                  <Link
                    href={`/dashboard/projects/new?project=${p.id}&url=${encodeURIComponent(p.github_url)}`}
                    className={cn(buttonVariants({ variant: "outline", size: "sm" }))}
                  >
                    Scan again
                  </Link>
                </li>
              ))}
            </ul>
          </CardContent>
        </Card>
      )}
    </div>
  );
}
