import { Sidebar } from "@/components/layout/sidebar";
import { Topbar } from "@/components/layout/topbar";

export default function DashboardLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <div className="min-h-screen bg-background">
      <Sidebar />
      <div className="flex min-h-screen flex-col lg:pl-64">
        <Topbar />
        <main className="flex-1 bg-background px-4 py-5 sm:px-6 lg:px-8">
          <div className="mx-auto w-full max-w-[90rem]">{children}</div>
        </main>
      </div>
    </div>
  );
}
