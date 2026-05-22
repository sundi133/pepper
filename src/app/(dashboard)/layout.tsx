import { Sidebar } from "@/components/layout/sidebar";
import { Topbar } from "@/components/layout/topbar";

export default function DashboardLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <div className="min-h-screen bg-background text-foreground">
      <Sidebar />
      <div className="flex min-h-screen min-w-0 flex-col lg:pl-64">
        <Topbar />
        <main className="flex-1 min-w-0 overflow-x-hidden px-4 py-5 sm:px-6 lg:px-8">
          <div className="page-shell min-w-0 max-w-full overflow-hidden">
            {children}
          </div>
        </main>
      </div>
    </div>
  );
}
