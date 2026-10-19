/**
 * Pepper for VS Code: a thin client for the Pepper language server
 * (ide/pepper-lsp). It keeps the API key in SecretStorage, starts the server,
 * and adds what LSP doesn't cover — sign-in, the status bar, the repository
 * picker and copying a finding. See docs/IDE_EXTENSION_SPEC.md §6.
 */
import * as vscode from "vscode";
import { ExecuteCommandRequest, LanguageClient, State, TransportKind, type LanguageClientOptions, type ServerOptions } from "vscode-languageclient/node";

const SECRET_KEY = "pepper.apiKey";
const REPOS_KEY = "pepper.repositories";

let client: LanguageClient | undefined;
let statusBar: vscode.StatusBarItem;
let context: vscode.ExtensionContext;

interface Counts { CRITICAL: number; HIGH: number; MEDIUM: number; LOW: number; INFO: number }
interface StatusNote { state: "ok" | "loading" | "signin" | "offline" | "no-repository" | "error"; message?: string; counts: Counts }

const config = () => vscode.workspace.getConfiguration("pepper");

function serverSettings() {
  const c = config();
  return {
    serverUrl: c.get<string>("serverUrl", "https://sast.votal.ai"),
    minSeverity: c.get<string>("minSeverity", "LOW"),
    checkOnSave: c.get<boolean>("checkOnSave", true) && vscode.workspace.isTrusted,
    branch: c.get<string>("branch", ""),
    refreshMinutes: c.get<number>("refreshMinutes", 10),
  };
}

function showStatus(note: StatusNote | { state: "signin" | "untrusted"; message?: string; counts?: Counts }) {
  const c = (note as StatusNote).counts;
  switch (note.state) {
    case "signin":
      statusBar.text = "$(shield) Pepper: sign in";
      statusBar.command = "pepper.signIn";
      break;
    case "untrusted":
      statusBar.text = "$(shield) Pepper: restricted";
      statusBar.command = undefined;
      break;
    case "loading":
      statusBar.text = "$(sync~spin) Pepper";
      statusBar.command = "pepper.refresh";
      break;
    case "offline":
      statusBar.text = "$(cloud-offline) Pepper: offline";
      statusBar.command = "pepper.refresh";
      break;
    case "no-repository":
      statusBar.text = "$(shield) Pepper: select repository";
      statusBar.command = "pepper.selectRepository";
      break;
    case "error":
      statusBar.text = "$(warning) Pepper";
      statusBar.command = "pepper.refresh";
      break;
    default: {
      const parts = c ? ([["CRITICAL", "critical"], ["HIGH", "high"], ["MEDIUM", "medium"]] as const).filter(([k]) => c[k] > 0).map(([k, l]) => `${c[k]} ${l}`) : [];
      statusBar.text = `$(shield) Pepper: ${parts.join(" · ") || "no open findings"}`;
      statusBar.command = "pepper.refresh";
    }
  }
  statusBar.tooltip = note.message ?? "Pepper: click to refresh findings";
  statusBar.show();
}

async function startClient(): Promise<void> {
  const apiKey = await context.secrets.get(SECRET_KEY);
  if (!apiKey) {
    showStatus({ state: "signin", message: "Sign in to Pepper to see findings in the editor" });
    return;
  }
  if (!vscode.workspace.isTrusted) {
    showStatus({ state: "untrusted", message: "Pepper needs a trusted workspace (it runs git and reads files)" });
    return;
  }
  const caFile = config().get<string>("caFile", "").trim();
  const env = { ...process.env, NODE_USE_ENV_PROXY: "1", ...(caFile ? { NODE_EXTRA_CA_CERTS: caFile } : {}) };
  const serverModule = context.asAbsolutePath("dist/server.js");
  const serverOptions: ServerOptions = {
    run: { module: serverModule, transport: TransportKind.ipc, options: { env } },
    debug: { module: serverModule, transport: TransportKind.ipc, options: { env, execArgv: ["--nolazy", "--inspect=6019"] } },
  };
  const s = serverSettings();
  const clientOptions: LanguageClientOptions = {
    documentSelector: [{ scheme: "file" }],
    synchronize: { configurationSection: "pepper" },
    initializationOptions: {
      serverUrl: s.serverUrl,
      apiKey,
      settings: s,
      repositories: context.workspaceState.get<Record<string, string>>(REPOS_KEY, {}),
      client: { pickRepository: true, statusNotifications: true },
    },
    diagnosticCollectionName: "pepper",
  };
  client = new LanguageClient("pepper", "Pepper", serverOptions, clientOptions);
  client.onNotification("pepper/status", (note: StatusNote) => showStatus(note));
  client.onNotification("pepper/repositoryChosen", async (p: { folderUri: string; repositoryId: string }) => {
    const saved = context.workspaceState.get<Record<string, string>>(REPOS_KEY, {});
    await context.workspaceState.update(REPOS_KEY, { ...saved, [p.folderUri]: p.repositoryId });
  });
  client.onRequest("pepper/pickRepository", async (p: { folderName: string; candidates: Array<{ id: string; name: string; repoUrl: string | null }> }) => {
    const pick = await vscode.window.showQuickPick(
      p.candidates.map((c) => ({ label: c.name, description: c.repoUrl ?? "", id: c.id })),
      { title: `Pepper repository for "${p.folderName}"`, placeHolder: "The repository whose scans to show for this folder", ignoreFocusOut: true },
    );
    return pick?.id ?? null;
  });
  showStatus({ state: "loading", message: "Starting Pepper…", counts: { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, INFO: 0 } });
  await client.start();
}

async function restartClient(): Promise<void> {
  if (client) {
    await client.stop().catch(() => undefined);
    client = undefined;
  }
  await startClient();
}

async function signIn(): Promise<void> {
  const serverUrl = await vscode.window.showInputBox({
    title: "Pepper server",
    prompt: "Your Pepper server URL (sast.votal.ai or your on-prem address)",
    value: config().get<string>("serverUrl", "https://sast.votal.ai"),
    ignoreFocusOut: true,
    validateInput: (v) => {
      try {
        const u = new URL(v.trim());
        const local = ["localhost", "127.0.0.1", "[::1]"].includes(u.hostname);
        return u.protocol === "https:" || (u.protocol === "http:" && local) ? null : "Use https:// (http:// only for localhost)";
      } catch {
        return "Enter a URL such as https://sast.votal.ai";
      }
    },
  });
  if (!serverUrl) return;
  const base = serverUrl.trim().replace(/\/+$/, "");
  const key = await vscode.window.showInputBox({
    title: "Pepper API key",
    prompt: `Create one in Pepper under Settings → API keys (${base}/settings/apikeys)`,
    password: true,
    ignoreFocusOut: true,
  });
  if (!key) return;
  const check = await vscode.window.withProgress({ location: vscode.ProgressLocation.Notification, title: "Pepper: checking the API key…" }, async () => {
    try {
      const res = await fetch(`${base}/api/ide/repository?all=true`, { headers: { authorization: `Bearer ${key.trim()}` } });
      return res.status === 200 ? null : res.status === 401 ? "The API key was not accepted" : `Pepper returned ${res.status}`;
    } catch (err) {
      return `Can't reach ${base}: ${err instanceof Error ? err.message : String(err)}`;
    }
  });
  if (check) {
    void vscode.window.showErrorMessage(`Pepper: ${check.split(key.trim()).join("[api key]")}`);
    return;
  }
  await config().update("serverUrl", base, vscode.ConfigurationTarget.Global);
  await context.secrets.store(SECRET_KEY, key.trim());
  void vscode.window.showInformationMessage("Pepper: signed in");
  await restartClient();
}

async function signOut(): Promise<void> {
  await context.secrets.delete(SECRET_KEY);
  if (client) {
    await client.stop().catch(() => undefined);
    client = undefined;
  }
  showStatus({ state: "signin", message: "Signed out of Pepper" });
}

export async function activate(ctx: vscode.ExtensionContext): Promise<void> {
  context = ctx;
  statusBar = vscode.window.createStatusBarItem(vscode.StatusBarAlignment.Left, 50);
  ctx.subscriptions.push(
    statusBar,
    vscode.commands.registerCommand("pepper.signIn", signIn),
    vscode.commands.registerCommand("pepper.signOut", signOut),
    vscode.commands.registerCommand("pepper.copyFinding", async (markdown: string) => {
      await vscode.env.clipboard.writeText(String(markdown ?? ""));
      void vscode.window.setStatusBarMessage("Pepper: finding copied", 2000);
    }),
    vscode.workspace.onDidChangeConfiguration((e) => {
      if (e.affectsConfiguration("pepper.caFile")) void restartClient();
    }),
    vscode.workspace.onDidGrantWorkspaceTrust(() => void restartClient()),
    ctx.secrets.onDidChange((e) => {
      if (e.key === SECRET_KEY) void restartClient();
    }),
  );
  // Palette commands forward to the language server (pepper.server.*), which
  // the language client registers for code actions. Without a running server
  // they offer to sign in.
  for (const name of ["refresh", "rescan", "scanWorkingTree", "selectRepository", "openInPepper"]) {
    ctx.subscriptions.push(
      vscode.commands.registerCommand(`pepper.${name}`, async () => {
        if (!client || client.state !== State.Running) {
          const choice = await vscode.window.showInformationMessage("Pepper: sign in first.", "Sign in");
          if (choice === "Sign in") await signIn();
          return;
        }
        await client.sendRequest(ExecuteCommandRequest.type, { command: `pepper.server.${name}`, arguments: [] });
      }),
    );
  }
  await startClient();
  if (!(await ctx.secrets.get(SECRET_KEY))) {
    const choice = await vscode.window.showInformationMessage("Pepper: sign in to see security findings in the editor.", "Sign in");
    if (choice === "Sign in") await signIn();
  }
}

export async function deactivate(): Promise<void> {
  await client?.stop().catch(() => undefined);
}
