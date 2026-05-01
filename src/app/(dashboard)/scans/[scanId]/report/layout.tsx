import { IBM_Plex_Mono, Source_Serif_4 } from "next/font/google";

/** Readable serif for report prose (replacing display-centric Syne). */
const reportSerif = Source_Serif_4({
  subsets: ["latin"],
  variable: "--pentest-serif",
  weight: ["400", "600", "700"],
});

const ibmMono = IBM_Plex_Mono({
  subsets: ["latin"],
  variable: "--pentest-mono",
  weight: ["400", "500", "600"],
});

export default function PentestReportLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <div
      className={`${reportSerif.variable} ${ibmMono.variable} min-h-screen antialiased`}
    >
      {children}
    </div>
  );
}
