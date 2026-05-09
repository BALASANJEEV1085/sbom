/** Must match apps/api listen port (default PORT=8081 in cmd/server). */
export const API_BASE =
  process.env.NEXT_PUBLIC_API_URL ?? "http://localhost:8081";

export class ApiError extends Error {
  constructor(
    public status: number,
    message: string,
    public body?: string,
  ) {
    super(message);
    this.name = "ApiError";
  }
}

async function readErrorBody(res: Response): Promise<string> {
  try {
    return await res.text();
  } catch {
    return res.statusText;
  }
}

/** Low-level JSON fetch with Bearer token. */
export async function apiFetchJson<T>(
  accessToken: string,
  path: string,
  init?: RequestInit,
): Promise<T> {
  const url = `${API_BASE}${path.startsWith("/") ? path : `/${path}`}`;
  const res = await fetch(url, {
    ...init,
    headers: {
      Accept: "application/json",
      "Content-Type": "application/json",
      Authorization: `Bearer ${accessToken}`,
      ...init?.headers,
    },
    cache: "no-store",
  });
  if (!res.ok) {
    const body = await readErrorBody(res);
    throw new ApiError(res.status, `HTTP ${res.status}`, body);
  }
  return (await res.json()) as T;
}

export type DashboardMetricsResponse = {
  total_projects: number;
  total_scans: number;
  critical_cves: number;
  clean_projects: number;
  recent_scans: {
    id: string;
    project_id: string;
    status: string;
    created_at: string;
    project_name: string;
    github_url: string;
    compliance_score?: number;
    ntia_compliant?: boolean;
  }[];
};

export async function getDashboardMetrics(
  accessToken: string,
): Promise<DashboardMetricsResponse> {
  return apiFetchJson<DashboardMetricsResponse>(
    accessToken,
    "/api/dashboard/metrics",
  );
}

export type CreateProjectResponse = {
  id: string;
  name: string;
  github_url: string;
};

export async function createProject(
  accessToken: string,
  githubUrl: string,
  name?: string,
): Promise<CreateProjectResponse> {
  return apiFetchJson<CreateProjectResponse>(accessToken, "/api/projects", {
    method: "POST",
    body: JSON.stringify({
      github_url: githubUrl,
      ...(name ? { name } : {}),
    }),
  });
}

export type StartScanResponse = {
  scan_id: string;
  status: string;
};

export async function startScan(
  accessToken: string,
  githubUrl: string,
  projectId: string,
): Promise<StartScanResponse> {
  return apiFetchJson<StartScanResponse>(accessToken, "/api/scans", {
    method: "POST",
    body: JSON.stringify({
      github_url: githubUrl,
      project_id: projectId,
    }),
  });
}

export type ScanComponent = {
  id: string;
  scan_id: string;
  name: string;
  version: string;
  version_spec: string;
  license: string;
  ecosystem: string;
  depth: number;
  parent_name: string;
  created_at: string;
};

export type GetScanResponse = {
  scan: {
    id: string;
    project_id: string;
    status: string;
    created_at: string;
  };
  components: ScanComponent[];
  total: number;
  project?: {
    name: string;
    github_url: string;
    display_title: string;
  };
};

export async function getScan(
  accessToken: string,
  scanId: string,
): Promise<GetScanResponse> {
  return apiFetchJson<GetScanResponse>(
    accessToken,
    `/api/scans/${encodeURIComponent(scanId)}`,
  );
}

export type ScanListItem = {
  id: string;
  project_id: string;
  status: string;
  created_at: string;
  project_name: string;
  github_url: string;
};

export async function listScans(accessToken: string): Promise<{
  scans: ScanListItem[];
  total: number;
}> {
  return apiFetchJson(accessToken, "/api/scans");
}

export type ProjectListItem = {
  id: string;
  name: string;
  github_url: string;
  created_at: string;
};

export async function listProjects(accessToken: string): Promise<{
  projects: ProjectListItem[];
  total: number;
}> {
  return apiFetchJson(accessToken, "/api/projects");
}
