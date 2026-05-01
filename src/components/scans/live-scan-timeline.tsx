"use client";

import { CheckCircle2, Circle, Loader2, TerminalSquare } from "lucide-react";
import type { ScanEvent } from "@/scanners/types";

const RESERVED = new Set([
  "liveScan",
  "architectureOverview",
  "rulesVersion",
]);

/** Keys under scannerProgress that are scanner status objects (badges), not metadata. */
export function isScannerProgressKey(key: string): boolean {
  return !RESERVED.has(key);
}

interface LiveScanTimelineProps {
  events: ScanEvent[] | undefined;
  isRunning: boolean;
}

function latestStep(events: ScanEvent[] | undefined): string | null {
  if (!events?.length) return null;
  const t = events[0]?.type;
  return t ?? null;
}

export function LiveScanTimeline({
  events,
  isRunning,
}: LiveScanTimelineProps) {
  const live = events ?? [];
  const step = latestStep(live);

  const milestones: { id: string; label: string; done: boolean; active: boolean }[] = [
    {
      id: "extract",
      label: "Extract / discover files",
      done: !!live.some((e) => e.type === "extract_completed"),
      active:
        step === "extract_started" ||
        (!!live.some((e) => e.type === "extract_started") &&
          !live.some((e) => e.type === "extract_completed")),
    },
    {
      id: "pattern",
      label: "Pattern / policy scan",
      done: !!live.some(
        (e) =>
          e.type === "scanner_completed" && e.scanner === "SAST_PATTERN",
      ),
      active: live.some(
        (e) =>
          e.type === "scanner_started" && e.scanner === "SAST_PATTERN",
      ),
    },
    {
      id: "llm",
      label: "LLM deep scan",
      done: !!live.some(
        (e) =>
          e.type === "scanner_completed" && e.scanner === "SAST_LLM",
      ),
      active: live.some(
        (e) =>
          e.type === "chunk_scanning" ||
          (e.type === "scanner_started" && e.scanner === "SAST_LLM"),
      ),
    },
    {
      id: "done",
      label: "Scan complete",
      done: live.some((e) => e.type === "scan_completed"),
      active: false,
    },
  ];

  return (
    <div className="space-y-3">
      <div className="flex flex-wrap gap-3 text-sm">
        {milestones.map((m) => (
          <div
            key={m.id}
            className="flex items-center gap-2 rounded-md border bg-muted/40 px-3 py-2"
          >
            {m.done ? (
              <CheckCircle2 className="h-4 w-4 text-green-600 shrink-0" />
            ) : m.active && isRunning ? (
              <Loader2 className="h-4 w-4 animate-spin text-primary shrink-0" />
            ) : (
              <Circle className="h-4 w-4 text-muted-foreground shrink-0" />
            )}
            <span
              className={
                m.active && isRunning ? "font-medium" : "text-muted-foreground"
              }
            >
              {m.label}
            </span>
          </div>
        ))}
      </div>
      {live.length > 0 && (
        <div className="rounded-lg border bg-background">
          <div className="flex items-center gap-2 border-b px-3 py-2 text-xs font-semibold uppercase tracking-wide text-muted-foreground">
            <TerminalSquare className="h-3.5 w-3.5" />
            Verbose scanner activity
          </div>
          <ul className="max-h-72 overflow-y-auto text-xs font-mono">
          {live.slice(0, 40).map((e, i) => (
            <li
              key={`${e.timestamp}-${i}`}
              className="border-b px-3 py-2 last:border-b-0"
            >
              <div className="flex flex-wrap items-center gap-x-2 gap-y-1">
                <span className="text-muted-foreground">
                  {new Date(e.timestamp).toLocaleTimeString()}
                </span>
                <span className="font-semibold">{eventTitle(e)}</span>
              </div>
              {e.type === "file_scanning" && (
                <div className="mt-1 truncate text-muted-foreground">
                  {e.filePath} ({e.currentFile}/{e.totalFiles})
                </div>
              )}
              {e.type === "chunk_scanning" && (
                <div className="mt-1 truncate text-muted-foreground">
                  {e.filePath} chunk {e.chunkIndex}/{e.totalChunks}
                </div>
              )}
              {e.type === "scan_progress" && (
                <div className="mt-1 whitespace-normal text-muted-foreground">
                  {e.message}
                </div>
              )}
              {e.type === "finding_found" && (
                <div className="mt-1 truncate text-muted-foreground">
                  {e.finding.title}
                </div>
              )}
            </li>
          ))}
          </ul>
        </div>
      )}
    </div>
  );
}

function eventTitle(event: ScanEvent): string {
  switch (event.type) {
    case "scan_started":
      return "Scan started";
    case "extract_started":
      return "Extracting source";
    case "extract_completed":
      return `Extracted ${event.totalFiles} files`;
    case "scanner_started":
      return `${event.scanner} started`;
    case "scanner_completed":
      return `${event.scanner} completed (${event.findingCount} findings)`;
    case "file_scanning":
      return `${event.scanner} file scan`;
    case "chunk_scanning":
      return "LLM chunk scan";
    case "finding_found":
      return `${event.scanner} finding`;
    case "scan_progress":
      return event.scanner ? `${event.scanner} progress` : "Scan progress";
    case "scan_completed":
      return `Scan completed (${event.findingCount} findings)`;
    case "scan_failed":
      return `Scan failed: ${event.error}`;
    default:
      return "Scan event";
  }
}
