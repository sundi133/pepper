import { redirect } from "next/navigation";
import { Sidebar } from "@/components/layout/sidebar";
import { Topbar } from "@/components/layout/topbar";
import { getSession, getActiveOrgId } from "@/lib/auth-guard";

export default async function DashboardLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  // Server-side gate: unauthenticated requests are redirected before any
  // dashboard page (and its data-bearing bundle) is rendered (VA-05).
  const session = await getSession();
  if (!session?.user?.id) {
    redirect("/login");
  }

  // Resolve the active org server-side (reads the httpOnly active_org cookie) so
  // the switcher can show which org is current.
  const activeOrgId = await getActiveOrgId(session);

  return (
    <div className="min-h-screen bg-background text-foreground">
      <Sidebar />
      <div className="flex min-h-screen min-w-0 flex-col lg:pl-64">
        <Topbar activeOrgId={activeOrgId} />
        <main className="flex-1 min-w-0 overflow-x-hidden px-4 py-5 sm:px-6 lg:px-8">
          <div className="page-shell min-w-0 max-w-full overflow-hidden">
            {children}
          </div>
        </main>
      </div>
    </div>
  );
}
