"use client";

import Link from "next/link";
import { usePathname, useRouter } from "next/navigation";
import { useEffect, useMemo, useState } from "react";
import {
  BarChart3,
  FolderKanban,
  LayoutDashboard,
  Settings,
  ShieldAlert,
  ShieldCheck,
  User,
} from "lucide-react";
import { cn } from "@/lib/utils";
import { Avatar, AvatarFallback } from "@/components/ui/avatar";
import {
  DropdownMenu,
  DropdownMenuGroup,
  DropdownMenuLabel,
  DropdownMenuSeparator,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";
import { Badge } from "@/components/ui/badge";
import { createClient } from "@/src/lib/supabase/client";
import type { User as SupabaseUser } from "@supabase/supabase-js";

export function Sidebar() {
  const pathname = usePathname();
  const router = useRouter();
  const [user, setUser] = useState<SupabaseUser | null>(null);
  const [mounted, setMounted] = useState(false);
  const [criticalCount, setCriticalCount] = useState(0);
  const [recentScan, setRecentScan] = useState<any | null>(null);

  useEffect(() => {
    setMounted(true);
    let isMounted = true;
    const controller = new AbortController();
    const supabase = createClient();

    // Initialize user and data
    const initializeUser = async () => {
      try {
        const {
          data: { user },
        } = await supabase.auth.getUser();
        
        if (!isMounted) return;
        setUser(user ?? null);
        
        if (user) {
          await fetchSidebarData(supabase, controller.signal);
        }
      } catch (error) {
        if (error instanceof Error && error.name !== "AbortError") {
          console.error("Failed to initialize user:", error);
        }
      }
    };

    initializeUser();

    // Subscribe to auth changes
    const {
      data: { subscription },
    } = supabase.auth.onAuthStateChange(async (_event, session) => {
      if (!isMounted) return;
      setUser(session?.user ?? null);
      if (session?.user) {
        await fetchSidebarData(supabase, controller.signal);
      }
    });

    async function fetchSidebarData(supabaseClient: ReturnType<typeof createClient>, signal: AbortSignal) {
      try {
        const {
          data: { session },
        } = await supabaseClient.auth.getSession();
        
        if (!session?.access_token || signal.aborted) return;

        // Fetch metrics
        const metricsRes = await fetch("http://localhost:8081/api/dashboard/metrics", {
          headers: { Authorization: `Bearer ${session.access_token}` },
          signal,
        });
        
        if (metricsRes.ok && isMounted) {
          const json = await metricsRes.json();
          if (json.recent_scans?.length > 0) {
            setRecentScan(json.recent_scans[0]);
          }
        }

        // Fetch vulnerabilities
        const vRes = await fetch("http://localhost:8081/api/vulnerabilities", {
          headers: { Authorization: `Bearer ${session.access_token}` },
          signal,
        });
        
        if (vRes.ok && isMounted) {
          const json = await vRes.json();
          if (json.summary?.critical) {
            setCriticalCount(json.summary.critical);
          }
        }
      } catch (error) {
        if (error instanceof Error && error.name !== "AbortError") {
          console.error("Failed to fetch sidebar data", error);
        }
      }
    }

    // Cleanup
    return () => {
      isMounted = false;
      controller.abort();
      subscription.unsubscribe();
    };
  }, []);

  const displayName = useMemo(() => {
    const metadata = user?.user_metadata;
    const name =
      metadata?.full_name ||
      metadata?.name ||
      metadata?.preferred_username ||
      metadata?.user_name;
    return name || user?.email || "User";
  }, [user]);

  const displayEmail = user?.email || "Not signed in";
  const avatarFallback = (displayName[0] || "U").toUpperCase();

  async function handleLogout() {
    const supabase = createClient();
    await supabase.auth.signOut();
    router.push("/");
    router.refresh();
  }

  const navItems = [
    { href: "/dashboard", label: "Dashboard", icon: LayoutDashboard },
    { href: "/dashboard/projects", label: "Projects", icon: FolderKanban },
    { href: "/dashboard/scans", label: "Scans", icon: ShieldCheck },
    {
      href: "/dashboard/vulnerabilities",
      label: "Vulnerabilities",
      icon: ShieldAlert,
      badge: criticalCount > 0,
    },
    { href: "/dashboard/reports", label: "Reports", icon: BarChart3 },
    { href: "/dashboard/settings", label: "Settings", icon: Settings },
  ];

  return (
    <aside className="sticky top-0 flex h-screen w-72 flex-col border-r bg-background p-5">
      <div className="mb-8">
        <p className="text-xl font-semibold tracking-tight">SBOM.io</p>
      </div>

      <nav className="flex-1 space-y-1.5">
        {navItems.map((item) => {
          const isActive = item.href === "/dashboard" 
            ? pathname === "/dashboard" 
            : pathname === item.href || pathname.startsWith(`${item.href}/`);
          const Icon = item.icon;

          return (
            <Link
              key={item.href}
              href={item.href}
              className={cn(
                "flex items-center gap-3 rounded-lg px-3 py-2 text-sm transition-colors hover:bg-muted hover:text-foreground",
                mounted && isActive ? "bg-muted text-foreground font-medium" : "text-muted-foreground"
              )}
            >
              <div className="relative">
                <Icon className="h-4 w-4" />
                {item.badge && mounted && (
                  <span className="absolute -right-1 -top-1 flex h-2 w-2 rounded-full bg-red-600" />
                )}
              </div>
              <span>{item.label}</span>
            </Link>
          );
        })}
      </nav>

      {mounted && recentScan && (
        <div className="mt-8 px-1">
          <div className="mb-2 px-3 flex items-center justify-between">
            <span className="text-[10px] font-bold uppercase tracking-wider text-muted-foreground">Recent Scan</span>
            {recentScan.compliance_score !== undefined && (
              <Badge variant={recentScan.ntia_compliant ? "default" : "destructive"} className="text-[9px] px-1 h-3.5 scale-90 origin-right">
                {recentScan.compliance_score}%
              </Badge>
            )}
          </div>
          <Link href={`/dashboard/scans/${recentScan.id}`} className="group flex flex-col gap-1 rounded-lg px-3 py-2 text-xs transition-colors hover:bg-muted border border-transparent hover:border-border">
            <span className="font-medium truncate text-foreground">{recentScan.project_name}</span>
            <span className="text-[10px] text-muted-foreground">{new Date(recentScan.created_at).toLocaleDateString()}</span>
          </Link>
        </div>
      )}

      <DropdownMenu>
        <DropdownMenuTrigger className="mt-4 flex w-full items-center justify-start gap-3 rounded-md px-2 py-2 text-left hover:bg-muted focus-visible:outline-none">
          <Avatar className="h-8 w-8">
            <AvatarFallback>{avatarFallback}</AvatarFallback>
          </Avatar>
          <div className="flex flex-col items-start">
            <span className="line-clamp-1 text-sm font-medium">{displayName}</span>
            <span className="line-clamp-1 text-xs text-muted-foreground">
              {displayEmail}
            </span>
          </div>
        </DropdownMenuTrigger>
        <DropdownMenuContent align="start" className="w-56">
          <DropdownMenuGroup>
            <DropdownMenuLabel className="truncate">{displayEmail}</DropdownMenuLabel>
          </DropdownMenuGroup>
          <DropdownMenuSeparator />
          <DropdownMenuItem className="gap-2">
            <User className="h-4 w-4" />
            Account
          </DropdownMenuItem>
          <DropdownMenuItem onClick={handleLogout}>Logout</DropdownMenuItem>
        </DropdownMenuContent>
      </DropdownMenu>
    </aside>
  );
}
