# IDE extension: Pepper findings in VS Code, JetBrains IDEs and Eclipse

Status: phase 1 implemented (`ide/`, `/api/ide/repository`, `/api/ide/findings` additions). Owner: Pepper developer experience.

## 1. Problem

Developers fix what they see while they code. Today Pepper's findings live in the web UI, in
PR comments, and with AI assistants through the MCP server (`/api/mcp`). There is no native
IDE experience:

- no squiggles or Problems-panel entries;
- no finding details on hover;
- no "scan now" from the editor;
- no instant check when a file is saved.

Procurement specifications (for example the STQC source code analysis tool spec) ask for IDE
integration in VS Code, Eclipse and IntelliJ.

The server side mostly exists:

| Capability | Endpoint | Auth |
|---|---|---|
| Latest findings for a repository, by file and severity | `GET /api/ide/findings?projectId=&filePath=&minSeverity=` | API key |
| Instant secrets and pattern check of file contents | `POST /api/precommit/scan` | API key |
| Start a scan (upload or repository URL) | `POST /api/scans` | session or API key |
| Rescan a repository from its last scan | `POST /api/scans/{id}/rescan` | session or API key |
| Scan status and progress | `GET /api/scans/{id}` | session or API key |
| Change a finding's status | `PATCH /api/findings/{id}` | session or API key (keys are capped at Developer) |

The gaps:

- **Finding the repository:** the IDE knows its git remote, not Pepper's repository id.
- **Moved lines:** findings come from the scanned commit, and the open file has changed since.
- **No client:** nothing turns findings into editor diagnostics.

## 2. Goals

1. **One implementation, three IDE families.** The logic lives in one language server,
   `pepper-lsp`. VS Code, JetBrains and Eclipse each get a thin client.
2. **Findings where the code is:** diagnostics on the right lines (re-anchored after edits),
   hover details, quick actions, a status bar summary, and a refresh.
3. **Fast feedback without AI cost:** saving a file runs the instant secrets and pattern
   check. AI scans run only on an explicit command.
4. **Works against any Pepper:** sast.votal.ai or on-prem, behind a proxy or an internal CA.
5. **Secure by default:**
   - the API key is kept in the IDE's secret storage and never logged;
   - TLS is required except for localhost;
   - no telemetry;
   - source code leaves the machine only for the on-save check (opt-out) and the explicit
     working-tree scan.
6. **No regressions:** existing endpoints keep their behaviour. New fields are additive, and
   new endpoints are new routes.

**Non-goals for phase 1:**

- the JetBrains and Eclipse plugins (phases 2 and 3; section 8);
- AI fix suggestions in the editor;
- triage decisions reserved for the Security role (false positive, accepted risk), which stay
  in the web UI.

## 3. Architecture

```
VS Code / Cursor / Windsurf       IntelliJ IDEA, PyCharm, WebStorm,     Eclipse
  pepper-vscode (TypeScript)        GoLand, Rider: LSP4IJ client       LSP4E client
            │                                  │                          │
            └──────────── stdio, Language Server Protocol ────────────────┘
                                       │
                         pepper-lsp (Node 18+, TypeScript)
                         repository resolution · findings cache · re-anchoring
                         diagnostics · hover · code actions · commands · on-save check
                                       │  HTTPS, Authorization: Bearer <API key>
                         Pepper API (sast.votal.ai or on-prem)
```

The code lives in `ide/`, separate from the app:

- `ide/pepper-lsp`: the language server. Pure modules (API client, re-anchoring, diagnostic
  mapping, zip writer) are tested by the repository's vitest suite. `server.ts` wires them to
  `vscode-languageserver`. Git remotes are normalized on the server (`src/lib/git-remote.ts`),
  so the IDE sends the raw remote.
- `ide/vscode`: the VS Code extension. It bundles `pepper-lsp` (esbuild), stores the API key
  in `SecretStorage`, and registers the commands, status bar and settings.

`ide/` is excluded from the app's TypeScript build and Docker images.

**Why LSP:** diagnostics, hover, code actions and commands are exactly the protocol's
features. All three IDE families have a mature LSP client: VS Code natively, LSP4IJ (works on
Community editions) and LSP4E. The JetBrains and Eclipse plugins then only launch the server
and add a settings page.

## 4. Server changes

### 4.1 `GET /api/ide/repository` (new)

Query: `remote` (a git remote URL), `name` (optional: the workspace folder name).

The remote is normalized by `normalizeGitRemote()`:

- `https://user:token@github.com/Org/Repo.git` → `github.com/org/repo`
- `git@github.com:Org/Repo.git` → `github.com/org/repo`
- `ssh://git@host:7999/team/repo.git` → `host/team/repo`
- Azure DevOps: `https://org@dev.azure.com/org/project/_git/repo` and
  `org@vs-ssh.visualstudio.com:v3/org/project/repo` → `dev.azure.com/org/project/repo`

Credentials are stripped, and the scheme, port, `.git` and trailing slashes are ignored.

It is matched against the organization's repositories:

1. `repoUrl` (normalized the same way);
2. the provider identity fields: GitHub owner and name, Bitbucket workspace and slug, Azure
   DevOps;
3. the repository name equal to the remote's last segment or to `name`.

It returns `{ repository: { id, name, repoUrl, defaultBranch } | null, matchedBy:
"url" | "provider" | "name" | null, candidates: [...] }`. `?all=true` returns every
repository as `candidates`, for a "change repository" picker. Auth uses the API-key principal,
so a key stops working once its creator leaves the organization. `candidates` lists up to 20
repositories, so the client can offer a picker when nothing matched or a name matched more
than one.

### 4.2 `GET /api/ide/findings` (additive changes)

- `repositoryId` is accepted as an alias for `projectId`.
- `branch` (optional): the latest completed scan **of that branch**; if there is none, the
  latest completed scan of the repository, as today. The response says which one it used
  (`scan.branch`).
- **Fields added per finding:** `snippet`, `remediation` and `attackPath` (from metadata),
  `validation` (the AI validator's verdict, for example `confirmed`), `riskScore`, and `url`
  (the scan's page in the web UI; there is no page per finding yet).
- **Status:** `RESOLVED` and `ACCEPTED_RISK` are excluded as well as `FALSE_POSITIVE`, since
  a developer doesn't need squiggles for them. `includeTriaged=true` restores the old set.
- The response gains `webBaseUrl` and `truncated` (more than 500 findings).

Existing callers keep working. The fields only grow. The status default narrows, which is
the documented purpose of the endpoint ("latest findings" to fix), and `includeTriaged=true`
restores the old behaviour.

### 4.3 Unchanged endpoints the client uses

`POST /api/precommit/scan`, `POST /api/scans`, `POST /api/scans/{id}/rescan`,
`GET /api/scans/{id}` and `PATCH /api/findings/{id}`.

**Working-tree scans:** an upload into the IDE's own repository would cancel that
repository's running scan (CI) and add a scan to its history. Instead, "Scan working tree"
uploads into a separate repository named `<repository> (local · <user>)`, created on first
use through `projectName`. It appears in the Repositories list like any other.

## 5. pepper-lsp behaviour

### 5.1 Settings

The client passes these in `initializationOptions` and `workspace/didChangeConfiguration`:

| Setting | Default | |
|---|---|---|
| `pepper.serverUrl` | `https://sast.votal.ai` | on-prem: the instance URL |
| API key | — | kept by the client in secret storage; sent to the server process in memory only |
| `pepper.minSeverity` | `LOW` | `INFO`, `LOW`, `MEDIUM`, `HIGH`, `CRITICAL` |
| `pepper.checkOnSave` | `true` | instant secrets and pattern check of the saved file |
| `pepper.branch` | current git branch | which branch's scan to show |
| `pepper.refreshMinutes` | 10 | background refresh; 0 turns it off |
| `pepper.caFile` | — | PEM file of an internal CA (in addition to the system roots) |

`HTTPS_PROXY`, `HTTP_PROXY` and `NO_PROXY` are honoured.

### 5.2 Repository resolution

For each workspace folder:

1. Read `remote.origin.url` (or the first remote) and the current branch with `git`.
2. Call `/api/ide/repository`.
3. If nothing matched, or it was ambiguous, ask the client to show a picker (`window/
   showMessageRequest`, or a client command in VS Code). The choice is remembered per
   folder.

A folder that is not a git repository uses the picker.

### 5.3 Findings to diagnostics

The latest findings for the folder's repository and branch are fetched once and cached.
Diagnostics are published per open document and refreshed:

- on open;
- on change (re-anchored from the cache, with no request);
- on refresh (command, interval, or after a scan completes).

| Pepper | Diagnostic |
|---|---|
| CRITICAL, HIGH | Error |
| MEDIUM | Warning |
| LOW | Information |
| INFO | Hint |

- `source`: `Pepper` (plus ` (on-save)` for instant-check results).
- `code`: CWE or rule id, with `codeDescription.href` linking to the finding page.
- Message: the title.

**Hover** shows the title, severity, scanner, CWE, description, attack path and remediation,
and links to the web UI.

**Code actions:**

- "Open in Pepper";
- "Mark in progress" and "Mark resolved" (allowed for API keys);
- "Copy finding" (as Markdown, for a ticket or an AI assistant).

### 5.4 Re-anchoring after edits

A finding's line refers to the scanned commit. For each finding with a snippet:

1. **Normalize the snippet:** strip line-number prefixes (`12: `) and blank or trivial lines
   (only brackets, punctuation, or shorter than 4 characters).
2. **Choose an anchor line:** the snippet line at the reported start line when the snippet
   is numbered; otherwise the longest remaining line.
3. **Search** the current document for that line (whitespace-insensitive) within ±200 lines
   of the reported line, and take the nearest match. Two matches at the same distance count
   as ambiguous.
4. **Found:** shift the range by the difference. **Not found or ambiguous:** keep the
   reported line (clamped to the document) and add "(code may have changed since the scan)"
   to the message.

A finding without a snippet keeps its reported line.

Findings for files that no longer exist are listed only in the status-bar summary.

### 5.5 On-save check

When `checkOnSave` is on, saving a file sends `{ path, content }` to
`/api/precommit/scan` (files over 1 MB are skipped). The results:

- appear as separate diagnostics (`Pepper (on-save)`), replaced on each save;
- are deduplicated against scan findings on the same line and CWE;
- are secrets and pattern findings only, with no AI.

### 5.6 Commands

The server executes `pepper.server.*` commands (`workspace/executeCommand`), so every LSP
client can call them. VS Code's palette entries (`pepper.refresh`, …) forward to them, and
offer to sign in when the server isn't running.

| Command | Behaviour |
|---|---|
| `pepper.refresh` | refetch findings for every folder |
| `pepper.rescan` | `POST /api/scans/{latest}/rescan` (the server clones the branch); poll `GET /api/scans/{id}` with progress until it completes; refresh |
| `pepper.scanWorkingTree` | ask for confirmation (file count, size, server); zip the git-tracked files (`git ls-files`, plus untracked unless ignored), up to 100 MB; upload with `projectName = "<repo> (local · <user>)"` and `scanType = SAST_ONLY`; poll; show the results from that scan |
| `pepper.selectRepository` | pick or change the repository for a folder |
| `pepper.openInPepper` | open the repository's latest scan in the browser |
| `pepper.signIn` / `pepper.signOut` | client-side: store or forget the API key, then restart the server |

### 5.7 Errors

| Response | What the user sees |
|---|---|
| 401 | "Pepper API key is missing or invalid": one notification and a sign-in action, no retry loop |
| 403 | "This API key can't do that" |
| 404 repository | the picker |
| 5xx or network | the status bar shows "offline"; retry with backoff up to the refresh interval; cached diagnostics stay |

## 6. VS Code extension

- **Contributes** the settings above, the commands (in the palette, plus "Pepper: Refresh"
  on the Problems view), and a status bar item: `Pepper: 2 critical · 5 high`, or `Pepper:
  offline` / `Pepper: sign in`. Clicking it refreshes.
- **First run:** "Sign in to Pepper" asks for the server URL and the API key. It links to
  `<server>/settings/apikeys` and verifies the key with a request before saving it.
- **Packaging:** esbuild bundles the client and the server into `dist/`; `vsce package`
  produces a `.vsix`. Published to the VS Code Marketplace and Open VSX (for Cursor and
  Windsurf), and attached to GitHub releases for offline installs.
- **Engine:** VS Code 1.91 or newer (`vscode-languageclient` 10).
- **Restricted Mode:** in an untrusted workspace the extension doesn't start the server, so
  it runs no git commands and sends no files.
- **Releases:** each `v*` tag attaches `pepper-sast-<version>.vsix` and the standalone server
  `pepper-lsp-<version>.js` to the GitHub release.

## 7. Security

- **API key:** kept only in `SecretStorage`. It is passed to the server process in
  `initializationOptions` (in memory, over stdio), never written to settings or logs, and
  redacted from any error the client shows.
- **TLS:** `http://` server URLs are refused except for localhost and 127.0.0.1.
- **Source sent to Pepper:**
  - the saved file, for the on-save check (setting; on by default);
  - the working tree, on an explicit command only.

  Both go only to the configured Pepper server.
- **Editor content is untrusted:** the client never runs commands that a finding or a
  server response asks for. Links open only under `serverUrl`.
- **No telemetry.**

## 8. Phases

1. **This change:**
   - `/api/ide/repository`;
   - the `/api/ide/findings` additions;
   - `pepper-lsp`;
   - the VS Code extension;
   - documentation on the IDE settings page.
2. **JetBrains plugin** (Kotlin): an LSP4IJ server definition that launches the bundled
   `pepper-lsp`, a settings page (server URL, API key in the IDE's credential store) and the
   same commands as actions. It needs Node 18+ on PATH in phase 2. A self-contained binary
   (Node single executable application) comes later.
3. **Eclipse plugin:** an LSP4E content-type binding and a preference page; the same server.
4. **Later:** AI fix suggestions (the remediation API) as code actions with a diff preview;
   a "changed files only" mode for a branch scan; a findings tree view.

## 9. Testing

- **Server:**
  - route tests for `/api/ide/repository`: URL forms, provider fields, name fallback,
    ambiguity, other organizations' repositories never returned;
  - route tests for `/api/ide/findings`: `repositoryId`, `branch` fallback, the status
    default and `includeTriaged`, new fields.
- **pepper-lsp unit tests** (vitest, `ide/**/*.test.ts`):
  - git remote normalization and repository matching (server side);
  - re-anchoring: moved, deleted, ambiguous, numbered and raw snippets;
  - severity mapping and diagnostic construction;
  - on-save dedupe;
  - API client errors (401, 403, network) and that the key never appears in messages.
- **End-to-end over LSP:** a script drives the bundled server over stdio against a mock
  Pepper API and a temporary git repository. It covers:
  - initialize, repository resolution and findings;
  - diagnostics, hover, code actions and re-anchoring after an edit;
  - the on-save secret check;
  - set status, open in Pepper (and refusing other hosts);
  - rescan with progress, and the working-tree upload with confirmation;
  - closing a document, and a wrong key.
- **Manual checks in VS Code before release** (in the PR):
  - sign in;
  - findings on an open file of a scanned repository;
  - an edit moves a squiggle with its code;
  - saving a file with a fake key shows an on-save finding;
  - rescan with progress;
  - offline handling.
