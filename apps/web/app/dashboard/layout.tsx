import { ReactNode } from "react";
import { Sidebar } from "@/src/components/sidebar";

type DashboardLayoutProps = {
  children: ReactNode;
};

export default function DashboardLayout({ children }: DashboardLayoutProps) {
  return (
    <div className="flex min-h-screen bg-muted/20 text-foreground">
      <Sidebar />
      <main className="flex-1 p-8 md:p-10">{children}</main>
    </div>
  );
}
