/**
 * Pepper language server (docs/IDE_EXTENSION_SPEC.md §5). Speaks LSP over
 * stdio, so any LSP client can host it: the VS Code extension (ide/vscode),
 * LSP4IJ in JetBrains IDEs, LSP4E in Eclipse.
 *
 * initializationOptions: { serverUrl, apiKey, settings?, repositories?: {folderUri: repositoryId}, client?: { pickRepository?, statusNotifications? } }
 */
import * as os from "os";
import * as path from "path";
import { promises as fsp, realpathSync } from "fs";
import { fileURLToPath, pathToFileURL } from "url";
import {
  CodeAction,
  CodeActionKind,
  createConnection,
  type Diagnostic as LspDiagnostic,
  type Hover,
  MarkupKind,
  ProposedFeatures,
  TextDocuments,
  TextDocumentSyncKind,
} from "vscode-languageserver/node";
import { TextDocument } from "vscode-languageserver-textdocument";
import { PepperApi, PepperApiError, TERMINAL_SCAN_STATES, scanPercent, type IdeFinding, type RepositoryRef, type ScanRef, type Severity } from "./api";
import {
  atLeast,
  countBySeverity,
  dedupeOnSave,
  findingDiagnostic,
  findingMarkdown,
  findingsForPath,
  indexByPath,
  precommitDiagnostic,
  type Counts,
  type Diagnostic,
} from "./diagnostics";
import { gitInfo, workingTreeFiles, type GitInfo } from "./git";
import { createZip } from "./zip";

interface Settings {
  serverUrl: string;
  minSeverity: Severity;
  checkOnSave: boolean;
  branch: string;
  refreshMinutes: number;
}

interface FolderState {
  uri: string;
  fsPath: string;
  git: GitInfo | null;
  repository: RepositoryRef | null;
  /** A working-tree scan's repository shown instead of the folder's own, until refresh. */
  localRepository: RepositoryRef | null;
  scan: ScanRef | null;
  findings: IdeFinding[];
  byPath: Map<string, IdeFinding[]>;
  webBaseUrl: string | null;
  error: string | null;
}

/**
 * Commands the server executes (workspace/executeCommand). Clients bind their
 * own UI to these; VS Code's palette entries (pepper.refresh, …) forward here.
 */
export const COMMANDS = {
  refresh: "pepper.server.refresh",
  rescan: "pepper.server.rescan",
  scanWorkingTree: "pepper.server.scanWorkingTree",
  selectRepository: "pepper.server.selectRepository",
  setStatus: "pepper.server.setStatus",
  openInPepper: "pepper.server.openInPepper",
} as const;
/** Handled by the client (no server-side effect). */
export const CLIENT_COMMANDS = { copyFinding: "pepper.copyFinding" } as const;

const MAX_ON_SAVE_BYTES = 1_000_000;
const MAX_UPLOAD_BYTES = 100 * 1024 * 1024;
const SEVERITIES: Severity[] = ["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"];

const connection = createConnection(ProposedFeatures.all);
const documents = new TextDocuments(TextDocument);

let settings: Settings = { serverUrl: "https://sast.votal.ai", minSeverity: "LOW", checkOnSave: true, branch: "", refreshMinutes: 10 };
let apiKey = "";
let api: PepperApi | null = null;
let clientFeatures = { pickRepository: false, statusNotifications: false };
let savedRepositories: Record<string, string> = {};
const folders = new Map<string, FolderState>();
const onSave = new Map<string, Diagnostic[]>();
const shown = new Map<string, Array<{ diag: Diagnostic; finding?: IdeFinding }>>();
const warned = new Set<string>();
let timer: NodeJS.Timeout | null = null;

// ─── Helpers ────────────────────────────────────────────────────────────────

/**
 * File URI to a real path: symlinks resolved, so an editor path through a
 * symlink (macOS /var → /private/var, a linked checkout) matches git's root.
 */
const toPath = (uri: string) => {
  let p: string;
  try {
    p = fileURLToPath(uri);
  } catch {
    return null;
  }
  try {
    return realpathSync.native(p);
  } catch {
    // A new, unsaved file: resolve its folder instead.
    try {
      return path.join(realpathSync.native(path.dirname(p)), path.basename(p));
    } catch {
      return p;
    }
  }
};

function applySettings(raw: unknown) {
  const s = (raw && typeof raw === "object" ? raw : {}) as Partial<Settings>;
  settings = {
    serverUrl: typeof s.serverUrl === "string" && s.serverUrl.trim() ? s.serverUrl.trim() : settings.serverUrl,
    minSeverity: SEVERITIES.includes(s.minSeverity as Severity) ? (s.minSeverity as Severity) : settings.minSeverity,
    checkOnSave: typeof s.checkOnSave === "boolean" ? s.checkOnSave : settings.checkOnSave,
    branch: typeof s.branch === "string" ? s.branch.trim() : settings.branch,
    refreshMinutes: typeof s.refreshMinutes === "number" && s.refreshMinutes >= 0 ? s.refreshMinutes : settings.refreshMinutes,
  };
  try {
    api = new PepperApi(settings.serverUrl, apiKey);
  } catch (err) {
    api = null;
    report(err);
  }
  schedule();
}

function schedule() {
  if (timer) clearInterval(timer);
  timer = settings.refreshMinutes > 0 ? setInterval(() => void refreshAll(), settings.refreshMinutes * 60_000) : null;
}

function folderFor(docPath: string): FolderState | undefined {
  let best: FolderState | undefined;
  for (const f of folders.values()) {
    const base = f.git?.root ?? f.fsPath;
    const rel = path.relative(base, docPath);
    if (!rel.startsWith("..") && !path.isAbsolute(rel) && (!best || base.length > (best.git?.root ?? best.fsPath).length)) best = f;
  }
  return best;
}

/** Status for the client's status bar; clients without the extension get a message once. */
function status(state: "ok" | "loading" | "signin" | "offline" | "no-repository" | "error", message?: string) {
  const counts = [...folders.values()].reduce<Counts>((acc, f) => {
    const c = countBySeverity(f.findings.filter((x) => atLeast(x.severity, settings.minSeverity)));
    for (const k of Object.keys(acc) as Array<keyof Counts>) acc[k] += c[k];
    return acc;
  }, { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, INFO: 0 });
  if (clientFeatures.statusNotifications) {
    void connection.sendNotification("pepper/status", { state, message, counts, folders: [...folders.values()].map((f) => ({ uri: f.uri, repository: f.localRepository ?? f.repository, scan: f.scan, error: f.error })) });
  } else if (message && (state === "signin" || state === "offline" || state === "error") && !warned.has(message)) {
    warned.add(message);
    void connection.window.showWarningMessage(`Pepper: ${message}`);
  }
}

function report(err: unknown): string {
  const e = err instanceof PepperApiError ? err : new PepperApiError("server", err instanceof Error ? err.message : String(err));
  const state = e.kind === "auth" ? "signin" : e.kind === "network" ? "offline" : "error";
  status(state, e.message);
  connection.console.warn(`Pepper: ${e.message}`);
  return e.message;
}

// ─── Loading ────────────────────────────────────────────────────────────────

async function pickRepository(f: FolderState, candidates: RepositoryRef[]): Promise<RepositoryRef | null> {
  if (!candidates.length) return null;
  const label = path.basename(f.fsPath);
  if (clientFeatures.pickRepository) {
    const id = await connection.sendRequest<string | null>("pepper/pickRepository", {
      folderUri: f.uri,
      folderName: label,
      candidates: candidates.map((c) => ({ id: c.id, name: c.name, repoUrl: c.repoUrl })),
    });
    return candidates.find((c) => c.id === id) ?? null;
  }
  const choice = await connection.window.showInformationMessage(
    `Pepper: which repository is "${label}"?`,
    ...candidates.slice(0, 8).map((c) => ({ title: c.name })),
  );
  return candidates.find((c) => c.name === choice?.title) ?? null;
}

async function resolveRepository(f: FolderState, ask: boolean): Promise<void> {
  if (!api) return;
  const saved = savedRepositories[f.uri];
  if (saved && !ask) {
    const { candidates } = await api.repositories();
    f.repository = candidates.find((c) => c.id === saved) ?? null;
    if (f.repository) return;
  }
  const res = ask ? { repository: null, candidates: (await api.repositories()).candidates } : await api.repository(f.git?.remote ?? null, path.basename(f.git?.root ?? f.fsPath));
  f.repository = res.repository ?? (await pickRepository(f, res.candidates));
  if (f.repository && clientFeatures.pickRepository) {
    savedRepositories[f.uri] = f.repository.id;
    void connection.sendNotification("pepper/repositoryChosen", { folderUri: f.uri, repositoryId: f.repository.id });
  }
}

async function loadFindings(f: FolderState): Promise<void> {
  if (!api) return;
  const repo = f.localRepository ?? f.repository;
  if (!repo) {
    f.findings = [];
    f.byPath = new Map();
    f.scan = null;
    return;
  }
  const branch = f.localRepository ? null : settings.branch || f.git?.branch || null;
  const res = await api.findings(repo.id, branch);
  f.scan = res.scan;
  f.findings = res.findings;
  f.byPath = indexByPath(res.findings);
  f.webBaseUrl = res.webBaseUrl ?? null;
}

async function loadFolder(uri: string, askRepository = false): Promise<void> {
  const fsPath = toPath(uri);
  if (!fsPath) return;
  const f: FolderState = folders.get(uri) ?? { uri, fsPath, git: null, repository: null, localRepository: null, scan: null, findings: [], byPath: new Map(), webBaseUrl: null, error: null };
  folders.set(uri, f);
  try {
    f.git = await gitInfo(fsPath);
    if (!f.repository || askRepository) await resolveRepository(f, askRepository);
    await loadFindings(f);
    f.error = null;
  } catch (err) {
    f.error = report(err);
  }
}

async function refreshAll(): Promise<void> {
  if (!api) return status("signin", "Sign in to Pepper: no API key is set");
  status("loading");
  for (const f of folders.values()) {
    try {
      await loadFindings(f);
      f.error = null;
    } catch (err) {
      f.error = report(err);
    }
  }
  finish();
}

/** Publish every open document and set the status from the folders' state. */
function finish(): void {
  documents.all().forEach(publish);
  const errors = [...folders.values()].filter((f) => f.error);
  if (!errors.length) {
    const unmapped = [...folders.values()].some((f) => !(f.localRepository ?? f.repository));
    status(unmapped ? "no-repository" : "ok", unmapped ? "Select the Pepper repository for this folder" : undefined);
  }
}

// ─── Diagnostics ────────────────────────────────────────────────────────────

function publish(doc: TextDocument): void {
  if (!documents.get(doc.uri)) return; // closed meanwhile (a delayed refresh after close)
  const docPath = toPath(doc.uri);
  if (!docPath) return;
  const f = folderFor(docPath);
  const lines = doc.getText().split(/\r?\n/);
  const entries: Array<{ diag: Diagnostic; finding?: IdeFinding }> = [];
  if (f) {
    const rel = path.relative(f.git?.root ?? f.fsPath, docPath).split(path.sep).join("/");
    for (const finding of findingsForPath(f.byPath, rel)) {
      if (atLeast(finding.severity, settings.minSeverity)) entries.push({ diag: findingDiagnostic(finding, lines), finding });
    }
  }
  const scanDiags = entries.map((e) => e.diag);
  for (const d of dedupeOnSave(onSave.get(doc.uri) ?? [], scanDiags)) entries.push({ diag: d });
  shown.set(doc.uri, entries);
  void connection.sendDiagnostics({ uri: doc.uri, diagnostics: entries.map((e) => e.diag as LspDiagnostic) });
}

const debounced = new Map<string, NodeJS.Timeout>();
documents.onDidChangeContent((e) => {
  clearTimeout(debounced.get(e.document.uri));
  debounced.set(e.document.uri, setTimeout(() => publish(e.document), 300));
});
documents.onDidOpen((e) => publish(e.document));
documents.onDidClose((e) => {
  clearTimeout(debounced.get(e.document.uri));
  debounced.delete(e.document.uri);
  onSave.delete(e.document.uri);
  shown.delete(e.document.uri);
  void connection.sendDiagnostics({ uri: e.document.uri, diagnostics: [] });
});
documents.onDidSave(async (e) => {
  if (!settings.checkOnSave || !api) return;
  const docPath = toPath(e.document.uri);
  const content = e.document.getText();
  if (!docPath || Buffer.byteLength(content) > MAX_ON_SAVE_BYTES) return;
  const f = folderFor(docPath);
  const rel = f ? path.relative(f.git?.root ?? f.fsPath, docPath).split(path.sep).join("/") : path.basename(docPath);
  try {
    const { findings } = await api.precommit([{ path: rel, content }]);
    const lines = content.split(/\r?\n/);
    onSave.set(e.document.uri, findings.filter((x) => atLeast(x.severity, settings.minSeverity)).map((x) => precommitDiagnostic(x, lines)));
    publish(e.document);
  } catch (err) {
    report(err);
  }
});

// ─── Hover and code actions ─────────────────────────────────────────────────

connection.onHover((p): Hover | null => {
  const hit = (shown.get(p.textDocument.uri) ?? []).find(
    (e) => e.finding && e.diag.range.start.line <= p.position.line && p.position.line <= e.diag.range.end.line,
  );
  if (!hit?.finding) return null;
  return { contents: { kind: MarkupKind.Markdown, value: findingMarkdown(hit.finding) }, range: hit.diag.range };
});

connection.onCodeAction((p): CodeAction[] => {
  const entries = shown.get(p.textDocument.uri) ?? [];
  const actions: CodeAction[] = [];
  for (const d of p.context.diagnostics) {
    const id = (d.data as Diagnostic["data"] | undefined)?.findingId;
    const finding = id ? entries.find((e) => e.finding?.id === id)?.finding : undefined;
    if (!finding) continue;
    const short = finding.title.replace(/^\[Zero-Day\]\s*/, "").slice(0, 60);
    const add = (title: string, command: string, args: unknown[]) =>
      actions.push({ title, kind: CodeActionKind.QuickFix, diagnostics: [d], command: { title, command, arguments: args } });
    if (finding.url) add(`Pepper: open "${short}" in Pepper`, COMMANDS.openInPepper, [finding.url]);
    add("Pepper: mark in progress", COMMANDS.setStatus, [finding.id, "IN_PROGRESS"]);
    add("Pepper: mark resolved", COMMANDS.setStatus, [finding.id, "RESOLVED"]);
    add("Pepper: copy finding", CLIENT_COMMANDS.copyFinding, [findingMarkdown(finding)]);
  }
  return actions;
});

// ─── Commands ───────────────────────────────────────────────────────────────

async function pollScan(scanId: string, title: string): Promise<string> {
  if (!api) throw new PepperApiError("auth", "Sign in to Pepper");
  const progress = await connection.window.createWorkDoneProgress();
  progress.begin(title, 0, "Queued", false);
  try {
    for (let i = 0; i < 720; i++) {
      const s = await api.scan(scanId);
      if (TERMINAL_SCAN_STATES.has(s.status)) return s.status;
      progress.report(scanPercent(s), s.status === "QUEUED" ? "Queued" : `Scanning… ${scanPercent(s)}%`);
      await new Promise((r) => setTimeout(r, 5_000));
    }
    return "TIMEOUT";
  } finally {
    progress.done();
  }
}

const targetFolders = (uri?: unknown) => (typeof uri === "string" && folders.has(uri) ? [folders.get(uri)!] : [...folders.values()]);

async function rescan(uri?: unknown) {
  for (const f of targetFolders(uri)) {
    if (!api || !f.scan) {
      void connection.window.showInformationMessage(`Pepper: "${path.basename(f.fsPath)}" has no completed scan to rescan yet. Use "Scan working tree", or scan it in Pepper first.`);
      continue;
    }
    f.localRepository = null;
    const { scanId } = await api.rescan(f.scan.id);
    const result = await pollScan(scanId, `Pepper: rescanning ${f.repository?.name ?? path.basename(f.fsPath)}`);
    void connection.window.showInformationMessage(`Pepper: rescan ${result.toLowerCase()}`);
  }
  await refreshAll();
}

async function scanWorkingTree(uri?: unknown) {
  if (!api) throw new PepperApiError("auth", "Sign in to Pepper");
  const f = targetFolders(uri)[0];
  if (!f?.git) {
    void connection.window.showWarningMessage("Pepper: scanning the working tree needs a git repository (to know which files to send).");
    return;
  }
  const files = await workingTreeFiles(f.git.root);
  const entries: Array<{ path: string; data: Uint8Array }> = [];
  let total = 0;
  for (const rel of files) {
    const data = await fsp.readFile(path.join(f.git.root, rel));
    total += data.length;
    if (total > MAX_UPLOAD_BYTES) {
      void connection.window.showWarningMessage("Pepper: the working tree is larger than the 100 MB upload limit; scan the repository in Pepper instead.");
      return;
    }
    entries.push({ path: rel, data });
  }
  const repoName = f.repository?.name ?? path.basename(f.git.root);
  // Source leaves the machine only on an explicit, confirmed request (spec §7).
  const ok = await connection.window.showWarningMessage(
    `Pepper: upload ${entries.length} files (${(total / 1024 / 1024).toFixed(1)} MB) of "${path.basename(f.git.root)}" to ${api.base} for a scan?`,
    { title: "Upload and scan" },
    { title: "Cancel" },
  );
  if (ok?.title !== "Upload and scan") return;
  const projectName = `${repoName} (local · ${os.userInfo().username})`.slice(0, 100);
  const zip = createZip(entries);
  const { scanId, projectId } = await api.uploadScan(zip, `${path.basename(f.git.root)}.zip`, projectName);
  const result = await pollScan(scanId, `Pepper: scanning the working tree of ${repoName}`);
  f.localRepository = { id: projectId, name: projectName, repoUrl: null, defaultBranch: "main" };
  void connection.window.showInformationMessage(`Pepper: working-tree scan ${result.toLowerCase()}. Showing its findings; "Pepper: Refresh" goes back to ${f.repository?.name ?? "the repository"}'s latest scan.`);
  await loadFindings(f);
  documents.all().forEach(publish);
  status("ok");
}

connection.onExecuteCommand(async (p) => {
  const args = p.arguments ?? [];
  try {
    switch (p.command) {
      case COMMANDS.refresh:
        for (const f of folders.values()) f.localRepository = null;
        return await refreshAll();
      case COMMANDS.rescan:
        return await rescan(args[0]);
      case COMMANDS.scanWorkingTree:
        return await scanWorkingTree(args[0]);
      case COMMANDS.selectRepository: {
        for (const f of targetFolders(args[0])) {
          f.localRepository = null;
          await loadFolder(f.uri, true);
        }
        return finish();
      }
      case COMMANDS.setStatus: {
        const [id, st] = args as [string, "IN_PROGRESS" | "RESOLVED" | "OPEN"];
        if (!api || !id || !["IN_PROGRESS", "RESOLVED", "OPEN"].includes(st)) return;
        await api.setStatus(id, st, "Updated from the IDE");
        return await refreshAll();
      }
      case COMMANDS.openInPepper: {
        let url = typeof args[0] === "string" ? args[0] : null;
        if (!url) {
          const f = targetFolders(args[1])[0];
          const base = f?.webBaseUrl ?? api?.base;
          url = f?.scan && base ? `${base}/scans/${f.scan.id}` : base ?? null;
        }
        // Only links under the configured server are opened (spec §7).
        if (url && api && (url.startsWith(`${api.base}/`) || url === api.base || (folderBase() && url.startsWith(`${folderBase()}/`)))) {
          await connection.window.showDocument({ uri: url, external: true });
        }
        return;
      }
    }
  } catch (err) {
    report(err);
  }
});

const folderBase = () => [...folders.values()].find((f) => f.webBaseUrl)?.webBaseUrl ?? null;

// ─── Lifecycle ──────────────────────────────────────────────────────────────

let initialFolders: string[] = [];

connection.onInitialize((params) => {
  const o = (params.initializationOptions ?? {}) as { serverUrl?: string; apiKey?: string; settings?: unknown; repositories?: Record<string, string>; client?: typeof clientFeatures };
  apiKey = typeof o.apiKey === "string" ? o.apiKey : "";
  clientFeatures = { pickRepository: !!o.client?.pickRepository, statusNotifications: !!o.client?.statusNotifications };
  savedRepositories = o.repositories ?? {};
  applySettings({ ...(o.settings as object), ...(o.serverUrl ? { serverUrl: o.serverUrl } : {}) });
  initialFolders = (params.workspaceFolders ?? []).map((w) => w.uri);
  if (!initialFolders.length && params.rootUri) initialFolders = [params.rootUri];
  if (!initialFolders.length && params.rootPath) initialFolders = [pathToFileURL(params.rootPath).toString()];
  return {
    capabilities: {
      textDocumentSync: { openClose: true, change: TextDocumentSyncKind.Incremental, save: { includeText: false } },
      hoverProvider: true,
      codeActionProvider: { codeActionKinds: [CodeActionKind.QuickFix] },
      executeCommandProvider: { commands: Object.values(COMMANDS) },
      workspace: { workspaceFolders: { supported: true, changeNotifications: true } },
    },
    serverInfo: { name: "pepper-lsp", version: "0.1.0" },
  };
});

connection.onInitialized(async () => {
  try {
    connection.workspace.onDidChangeWorkspaceFolders(async (e) => {
      for (const r of e.removed) folders.delete(r.uri);
      for (const a of e.added) await loadFolder(a.uri);
      finish();
    });
  } catch {
    // client doesn't support folder change notifications
  }
  if (!api) return status("signin", "Sign in to Pepper: no API key is set");
  status("loading");
  for (const uri of initialFolders) await loadFolder(uri);
  finish();
});

connection.onDidChangeConfiguration((p) => {
  const s = (p.settings as { pepper?: unknown } | undefined)?.pepper;
  if (s) {
    applySettings(s);
    void refreshAll();
  }
});

connection.onShutdown(() => {
  if (timer) clearInterval(timer);
});

documents.listen(connection);
connection.listen();
