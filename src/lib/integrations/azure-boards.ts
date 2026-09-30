/**
 * Azure Boards work items for findings — Azure DevOps Services and Azure
 * DevOps Server (on-prem). Pure payload builders plus thin REST calls; the
 * database side (dedupe, fix sync) lives in finding-tickets.ts.
 */
import {
  azureApiBase,
  azureGet,
  azureJsonPatch,
  parseAzureErrorBody,
  type AzureDevOpsAuth,
  type AzureDevOpsResponse,
  type JsonPatchOp,
} from "@/lib/azure-devops-api";
import type { AzureBoardsConfig } from "./types";

export const AZURE_BOARDS_SYSTEM = "AZURE_BOARDS";
const DEFAULT_WORK_ITEM_TYPE = "Bug";
/** Work item titles are capped at 255 characters. */
const MAX_TITLE = 255;

type Severity = "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "INFO";

export interface BoardsFindingInput {
  pepperFindingId: string;
  title: string;
  severity: Severity;
  description: string;
  scanner?: string | null;
  filePath?: string | null;
  line?: number | null;
  snippet?: string | null;
  ruleId?: string | null;
  cveId?: string | null;
  cweId?: string | null;
  projectName?: string | null;
  scanUrl?: string;
}

export interface WorkItemRef {
  id: string;
  url: string;
}

/** Work item type, falling back to Bug. */
export function workItemTypeOf(config: AzureBoardsConfig): string {
  return config.workItemType?.trim() || DEFAULT_WORK_ITEM_TYPE;
}

/** Basic-process projects have Issue instead of Bug (Agile, Scrum and CMMI have Bug). */
const BASIC_PROCESS_WORK_ITEM_TYPE = "Issue";
/** Type found to exist per board, for boards that leave the type blank. */
const resolvedWorkItemTypes = new Map<string, string>();

function workItemTypeKey(auth: AzureDevOpsAuth, project: string): string {
  return `${azureApiBase(auth)}/${project}`.toLowerCase();
}

/** The configured type; if blank, Bug then Issue, unless one is already known to exist. */
function workItemTypesToTry(auth: AzureDevOpsAuth, config: AzureBoardsConfig, project: string): string[] {
  const configured = config.workItemType?.trim();
  if (configured) return [configured];
  const known = resolvedWorkItemTypes.get(workItemTypeKey(auth, project));
  return known ? [known] : [DEFAULT_WORK_ITEM_TYPE, BASIC_PROCESS_WORK_ITEM_TYPE];
}

function rememberWorkItemType(auth: AzureDevOpsAuth, config: AzureBoardsConfig, project: string, type: string) {
  if (!config.workItemType?.trim()) resolvedWorkItemTypes.set(workItemTypeKey(auth, project), type);
}

/** ADO's answer when a work item type doesn't exist in the project (VS402323). */
function isMissingWorkItemType(res: AzureDevOpsResponse<unknown>): boolean {
  if (res.status !== 404 && res.status !== 400) return false;
  return res.status === 404 || /VS402323|work item type .* does not exist/i.test(parseAzureErrorBody(res.data, res.raw) || "");
}

/** Why a Project value can't be a project name, or null. */
function projectNameError(project: string | undefined): string | null {
  const p = project?.trim();
  if (p && /[\\/]/.test(p)) {
    return `Project must be the Azure DevOps project name only (e.g. "${p.split(/[\\/]/)[0]}"), not "${p}"`;
  }
  return null;
}

/**
 * The board's identity — where work items land. Stable across integration
 * re-creation so dedupe survives deleting and re-adding the same board.
 */
export function boardsTarget(config: AzureBoardsConfig, project: string): string {
  const host = config.serverUrl?.trim().replace(/\/+$/, "").toLowerCase() || "https://dev.azure.com";
  return `${host}/${config.organization.trim().toLowerCase()}/${project.trim().toLowerCase()}`;
}

const TICKET_SEVERITIES = new Set(["CRITICAL", "HIGH", "MEDIUM", "LOW"]);

/** Why a submitted config is unusable, or null when it's fine. */
export function boardsConfigError(config: Partial<AzureBoardsConfig> | undefined): string | null {
  if (!config || typeof config !== "object") return "config is required";
  if (typeof config.organization !== "string" || !config.organization.trim()) {
    return "Organization (or collection, on Azure DevOps Server) is required";
  }
  if (config.serverUrl?.trim()) {
    try {
      const u = new URL(config.serverUrl.trim());
      if (u.protocol !== "https:" && u.protocol !== "http:") return "Server URL must be http(s)";
    } catch {
      return "Server URL is not a valid URL";
    }
  }
  const projectError = projectNameError(config.project);
  if (projectError) return projectError;
  if (config.autoCreateSeverities && !config.autoCreateSeverities.every((s) => TICKET_SEVERITIES.has(s))) {
    return "autoCreateSeverities must be CRITICAL, HIGH, MEDIUM or LOW";
  }
  if (config.tags && !(Array.isArray(config.tags) && config.tags.every((t) => typeof t === "string"))) {
    return "tags must be a list of strings";
  }
  return null;
}

/**
 * With no Server URL the board is Azure DevOps Services (dev.azure.com). When
 * the org's repo connection is an Azure DevOps Server and the board reuses its
 * PAT or names the same collection, the board is on that server.
 */
function inferredServerUrl(config: AzureBoardsConfig, orgConnection: AzureDevOpsAuth | null): string | undefined {
  const connectionServer = orgConnection?.serverUrl?.trim();
  if (!connectionServer) return undefined;
  const reusesConnectionPat = !config.pat?.trim();
  const sameCollection =
    config.organization.trim().toLowerCase() === orgConnection!.organization.trim().toLowerCase();
  return reusesConnectionPat || sameCollection ? connectionServer : undefined;
}

/** Credentials for the board: the integration's own PAT, else the org's repo connection. */
export function boardsAuth(
  config: AzureBoardsConfig,
  orgConnection: AzureDevOpsAuth | null,
): AzureDevOpsAuth | null {
  const pat = config.pat?.trim() || orgConnection?.pat;
  if (!pat || !config.organization?.trim()) return null;
  const serverUrl = config.serverUrl?.trim() || inferredServerUrl(config, orgConnection);
  return {
    organization: config.organization.trim(),
    pat,
    ...(serverUrl ? { serverUrl } : {}),
  };
}

// ─── Rendering ───────────────────────────────────────────────────────────────

function escapeHtml(s: string): string {
  return s
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

function inline(s: string): string {
  return escapeHtml(s)
    .replace(/`([^`\n]+)`/g, "<code>$1</code>")
    .replace(/\*\*([^*\n]+)\*\*/g, "<b>$1</b>");
}

/**
 * Finding descriptions are Markdown-ish text that can quote repository
 * content, so everything is escaped first and only a small, fixed set of
 * tags (paragraphs, lists, code, bold) is produced.
 */
export function markdownToSafeHtml(text: string): string {
  const out: string[] = [];
  const parts = text.replace(/\r\n/g, "\n").split(/```[^\n]*\n?/);
  parts.forEach((part, i) => {
    if (i % 2 === 1) {
      out.push(`<pre><code>${escapeHtml(part.replace(/\n$/, ""))}</code></pre>`);
      return;
    }
    for (const block of part.split(/\n{2,}/)) {
      const lines = block.split("\n").filter((l) => l.trim());
      if (lines.length === 0) continue;
      if (lines.every((l) => /^\s*[-*]\s+/.test(l))) {
        out.push(`<ul>${lines.map((l) => `<li>${inline(l.replace(/^\s*[-*]\s+/, ""))}</li>`).join("")}</ul>`);
      } else {
        out.push(`<p>${lines.map(inline).join("<br>")}</p>`);
      }
    }
  });
  return out.join("");
}

export function workItemTitle(f: BoardsFindingInput): string {
  const title = `[${f.severity}] ${f.title.replace(/\s+/g, " ").trim()}`;
  return title.length > MAX_TITLE ? `${title.slice(0, MAX_TITLE - 1)}…` : title;
}

export function workItemHtml(f: BoardsFindingInput): string {
  const where = f.filePath ? (f.line ? `${f.filePath}:${f.line}` : f.filePath) : null;
  const rows: Array<[string, string]> = [["Severity", escapeHtml(f.severity)]];
  if (f.projectName) rows.push(["Repository", escapeHtml(f.projectName)]);
  if (where) rows.push(["Location", `<code>${escapeHtml(where)}</code>`]);
  if (f.ruleId) rows.push(["Rule", escapeHtml(f.ruleId)]);
  if (f.cweId) rows.push(["CWE", escapeHtml(f.cweId)]);
  if (f.cveId) rows.push(["CVE", escapeHtml(f.cveId)]);
  if (f.scanner) rows.push(["Scanner", escapeHtml(f.scanner)]);
  if (f.scanUrl) rows.push(["Pepper", `<a href="${escapeHtml(f.scanUrl)}">Open the scan in Pepper</a>`]);

  const html = [
    markdownToSafeHtml(f.description.trim()),
    f.snippet?.trim() ? `<p><b>Code</b></p><pre><code>${escapeHtml(f.snippet.trim())}</code></pre>` : "",
    `<table>${rows.map(([k, v]) => `<tr><td><b>${k}</b></td><td>${v}</td></tr>`).join("")}</table>`,
    `<p><i>Filed by Pepper (finding ${escapeHtml(f.pepperFindingId)}). Pepper comments here when later scans no longer detect it.</i></p>`,
  ];
  return html.filter(Boolean).join("");
}

/** ADO tags are `; `-separated and can't contain `;` or `,`. */
export function workItemTags(config: AzureBoardsConfig, f: BoardsFindingInput): string {
  const tags = [
    "pepper",
    "security",
    `severity-${f.severity.toLowerCase()}`,
    f.cweId,
    f.cveId,
    ...(config.tags ?? []),
  ]
    .filter((t): t is string => Boolean(t && t.trim()))
    .map((t) => t.replace(/[;,]/g, " ").trim());
  return [...new Set(tags)].join("; ");
}

const PRIORITY: Record<Severity, number> = { CRITICAL: 1, HIGH: 2, MEDIUM: 3, LOW: 4, INFO: 4 };
const BUG_SEVERITY: Record<Severity, string> = {
  CRITICAL: "1 - Critical",
  HIGH: "2 - High",
  MEDIUM: "3 - Medium",
  LOW: "4 - Low",
  INFO: "4 - Low",
};

/**
 * JSON Patch for a new work item. `withOptionalFields` adds Priority, Bug
 * Severity and Repro Steps — present on the stock Agile / Scrum / CMMI / Basic
 * types but possibly missing from customised ones, so creation retries
 * without them. Area, iteration and assignee are the admin's explicit
 * choices and are always sent, so a typo surfaces as an error instead of work
 * items silently landing in the wrong place.
 */
export function buildWorkItemOps(
  config: AzureBoardsConfig,
  f: BoardsFindingInput,
  withOptionalFields: boolean,
): JsonPatchOp[] {
  const field = (name: string, value: unknown): JsonPatchOp => ({ op: "add", path: `/fields/${name}`, value });
  const html = workItemHtml(f);
  const ops: JsonPatchOp[] = [
    field("System.Title", workItemTitle(f)),
    field("System.Description", html),
    field("System.Tags", workItemTags(config, f)),
  ];
  if (config.areaPath?.trim()) ops.push(field("System.AreaPath", config.areaPath.trim()));
  if (config.iterationPath?.trim()) ops.push(field("System.IterationPath", config.iterationPath.trim()));
  if (config.assignedTo?.trim()) ops.push(field("System.AssignedTo", config.assignedTo.trim()));
  if (withOptionalFields) {
    ops.push(field("Microsoft.VSTS.Common.Priority", PRIORITY[f.severity]));
    if (workItemTypeOf(config).toLowerCase() === "bug") {
      // The Bug form shows Repro Steps rather than Description.
      ops.push(field("Microsoft.VSTS.TCM.ReproSteps", html));
      ops.push(field("Microsoft.VSTS.Common.Severity", BUG_SEVERITY[f.severity]));
    }
  }
  if (f.scanUrl) {
    ops.push({ op: "add", path: "/relations/-", value: { rel: "Hyperlink", url: f.scanUrl, attributes: { comment: "Pepper scan" } } });
  }
  return ops;
}

// ─── REST ────────────────────────────────────────────────────────────────────

/** Readable error, with hints for the usual on-prem / PAT problems. */
export function boardsError(action: string, res: AzureDevOpsResponse<unknown>, auth?: AzureDevOpsAuth): Error {
  // A bad PAT often gets 203 + an HTML sign-in page instead of a 401.
  if (res.status === 401 || res.status === 203) {
    const server = auth?.serverUrl?.trim();
    let host = "dev.azure.com";
    try {
      if (server) host = new URL(server).host;
    } catch {
      host = server!;
    }
    const where = server
      ? `the Server URL (${host})`
      : "the Server URL: it's blank, which means Azure DevOps Services (dev.azure.com); set it for Azure DevOps Server";
    return new Error(
      `${action} failed: ${host} rejected the PAT. Check ${where}, and that the PAT has the Work Items (Read & write) scope.`,
    );
  }
  if (res.status === 403) {
    return new Error(`${action} failed (403): the PAT's user can't create work items in this project.`);
  }
  const message = parseAzureErrorBody(res.data, res.raw) || `HTTP ${res.status}`;
  const hint = /api-version|out of range|VssVersionOutOfRange/i.test(message)
    ? " Set the API version for your Azure DevOps Server (e.g. 6.0 for Server 2020, 7.0 for Server 2022)."
    : "";
  return new Error(`${action} failed (${res.status}): ${message.slice(0, 300)}${hint}`);
}

function webUrl(auth: AzureDevOpsAuth, project: string, id: string, data: unknown): string {
  const href = (data as { _links?: { html?: { href?: string } } })?._links?.html?.href;
  return href || `${azureApiBase(auth)}/${encodeURIComponent(project)}/_workitems/edit/${id}`;
}

export async function createWorkItem(
  auth: AzureDevOpsAuth,
  config: AzureBoardsConfig,
  project: string,
  f: BoardsFindingInput,
): Promise<WorkItemRef> {
  const types = workItemTypesToTry(auth, config, project);
  let res!: AzureDevOpsResponse<{ id?: number }>;
  for (const [i, type] of types.entries()) {
    const typed = { ...config, workItemType: type };
    const path = `/${encodeURIComponent(project)}/_apis/wit/workitems/$${encodeURIComponent(type)}`;
    res = await azureJsonPatch<{ id?: number }>(auth, "POST", path, buildWorkItemOps(typed, f, true), config.apiVersion);
    if (res.status === 400 && !isMissingWorkItemType(res)) {
      // Likely a customised type without Priority / Severity / Repro Steps.
      res = await azureJsonPatch<{ id?: number }>(auth, "POST", path, buildWorkItemOps(typed, f, false), config.apiVersion);
    }
    if (isMissingWorkItemType(res) && i < types.length - 1) continue;
    if (res.ok && res.status !== 203 && res.data?.id != null) rememberWorkItemType(auth, config, project, type);
    break;
  }
  if (!res.ok || res.status === 203 || res.data?.id == null) throw boardsError("Azure Boards create", res, auth);
  const id = String(res.data.id);
  return { id, url: webUrl(auth, project, id, res.data) };
}

/** States a work item shouldn't be moved out of by Pepper. */
const TERMINAL_STATES = new Set(["closed", "done", "removed", "resolved", "completed", "cut"]);

/**
 * Tell the work item Pepper no longer detects the issue: always a History
 * comment, plus a state change when `fixedState` is set and nobody has closed
 * it yet. Returns false when the work item no longer exists.
 */
export async function markWorkItemFixed(
  auth: AzureDevOpsAuth,
  config: AzureBoardsConfig,
  project: string,
  id: string,
  note: { scanUrl?: string; branch?: string | null; scans?: number },
): Promise<boolean> {
  const itemPath = `/${encodeURIComponent(project)}/_apis/wit/workitems/${encodeURIComponent(id)}`;
  const current = await azureGet<{ fields?: Record<string, unknown> }>(auth, `${itemPath}?fields=System.State`, config.apiVersion);
  if (current.status === 404) return false;
  if (!current.ok || current.status === 203) throw boardsError("Azure Boards read", current, auth);

  const state = String(current.data.fields?.["System.State"] ?? "");
  const link = note.scanUrl ? ` <a href="${escapeHtml(note.scanUrl)}">View the scan</a>.` : "";
  const comment: JsonPatchOp = {
    op: "add",
    path: "/fields/System.History",
    value: `<p><b>Pepper no longer detects this issue</b> in the latest ${
      (note.scans ?? 1) > 1 ? `${note.scans} scans` : "scan"
    }${note.branch ? ` of <code>${escapeHtml(note.branch)}</code>` : ""}, so it looks fixed. Reopen if that's wrong.${link}</p>`,
  };
  const fixedState = config.fixedState?.trim();
  const move = fixedState && !TERMINAL_STATES.has(state.toLowerCase()) && state.toLowerCase() !== fixedState.toLowerCase();

  let res = await azureJsonPatch(auth, "PATCH", itemPath, move ? [comment, { op: "add", path: "/fields/System.State", value: fixedState }] : [comment], config.apiVersion);
  if (move && res.status === 400) {
    // The state isn't valid for this type / transition — still leave the comment.
    res = await azureJsonPatch(auth, "PATCH", itemPath, [comment], config.apiVersion);
  }
  if (!res.ok || res.status === 203) throw boardsError("Azure Boards update", res, auth);
  return true;
}

/** Comment that a previously fixed issue was detected again. */
export async function noteWorkItemRegressed(
  auth: AzureDevOpsAuth,
  config: AzureBoardsConfig,
  project: string,
  id: string,
  note: { scanUrl?: string },
): Promise<void> {
  const link = note.scanUrl ? ` <a href="${escapeHtml(note.scanUrl)}">View the scan</a>.` : "";
  const res = await azureJsonPatch(
    auth,
    "PATCH",
    `/${encodeURIComponent(project)}/_apis/wit/workitems/${encodeURIComponent(id)}`,
    [{ op: "add", path: "/fields/System.History", value: `<p><b>Pepper detected this issue again</b> after reporting it no longer detected.${link}</p>` }],
    config.apiVersion,
  );
  if (res.status === 404) return;
  if (!res.ok || res.status === 203) throw boardsError("Azure Boards update", res, auth);
}

/**
 * Check the board is usable without creating anything: the PAT can read work
 * item metadata, and — when a project is set — the project and work item
 * type exist and the area / iteration paths resolve.
 */
export async function validateBoardsConfig(
  auth: AzureDevOpsAuth,
  config: AzureBoardsConfig,
  project: string | null,
): Promise<{ workItemType: string }> {
  if (!project) {
    // Organization-level call that only needs the Work Items scope.
    const res = await azureGet(auth, "/_apis/wit/fields/System.Title", config.apiVersion);
    if (!res.ok || res.status === 203) throw boardsError("Azure Boards check", res, auth);
    return { workItemType: workItemTypeOf(config) };
  }
  const projectError = projectNameError(project);
  if (projectError) throw new Error(projectError);
  const p = encodeURIComponent(project);
  const types = workItemTypesToTry(auth, config, project);
  let res!: AzureDevOpsResponse<{ name?: string }>;
  let type = types[0];
  for (type of types) {
    res = await azureGet<{ name?: string }>(auth, `/${p}/_apis/wit/workitemtypes/${encodeURIComponent(type)}`, config.apiVersion);
    if (res.status !== 404) break;
  }
  if (res.status === 404) {
    throw new Error(
      types.length > 1
        ? `Project "${project}" was not found, or it has neither a "Bug" nor an "Issue" work item type. Check the project name, or set the work item type.`
        : `Project "${project}" or work item type "${type}" was not found. Basic-process projects use "Issue" instead of "Bug".`,
    );
  }
  if (!res.ok || res.status === 203) throw boardsError("Azure Boards check", res, auth);
  rememberWorkItemType(auth, config, project, res.data.name || type);

  for (const [kind, value] of [["Areas", config.areaPath], ["Iterations", config.iterationPath]] as const) {
    const path = value?.trim();
    if (!path) continue;
    // Node paths are `Project\Sub\Node`; the API wants the part after the project.
    const segments = path.split("\\").filter(Boolean);
    const sub = segments[0]?.toLowerCase() === project.toLowerCase() ? segments.slice(1) : segments;
    const node = await azureGet(auth, `/${p}/_apis/wit/classificationnodes/${kind}/${sub.map(encodeURIComponent).join("/")}`, config.apiVersion);
    if (node.status === 404) throw new Error(`${kind === "Areas" ? "Area" : "Iteration"} path "${path}" was not found in "${project}".`);
    if (!node.ok || node.status === 203) throw boardsError("Azure Boards check", node, auth);
  }
  return { workItemType: res.data.name || type };
}
