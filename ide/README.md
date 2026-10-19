# Pepper IDE integrations

See `docs/IDE_EXTENSION_SPEC.md` for the design.

| Folder | What |
|---|---|
| `pepper-lsp/` | The Pepper language server (Node 18+, LSP over stdio or IPC). It holds all the logic: repository resolution, findings, re-anchoring, diagnostics, hover, code actions, rescans and the on-save check |
| `vscode/` | The VS Code extension: a thin client that bundles the server |

## Develop

```bash
cd ide
npm install
npm run typecheck
npm run build                  # ide/vscode/dist/{extension,server}.js
npm run package                # ide/vscode/pepper-sast.vsix
```

The language server's pure modules are tested by the repository's suite (`npx vitest run
ide` from the repository root). To try the extension, open `ide/vscode` in VS Code and press
F5, or install the `.vsix` with **Extensions: Install from VSIX…**.

## Use the server from other IDEs

`pepper-lsp` is a standard language server, so any LSP client can host it. Build it with
`npm run build -w pepper-lsp`, which produces `ide/pepper-lsp/dist/server.js`. Then start it
with `node /path/to/server.js --stdio`.

The client must send `initializationOptions`:

```json
{
  "serverUrl": "https://sast.votal.ai",
  "apiKey": "<Pepper API key>",
  "settings": { "minSeverity": "LOW", "checkOnSave": true, "refreshMinutes": 10 }
}
```

Keep the key out of shared project files.

- **JetBrains IDEs (IntelliJ IDEA, PyCharm, WebStorm, GoLand, Rider; Community editions
  too):**
  1. Install the **LSP4IJ** plugin.
  2. Under *Settings → Languages & Frameworks → Language Servers*, add a server with the
     command `node /path/to/server.js --stdio`, file mappings for your languages, and the
     initialization options above.
- **Eclipse:** use **LSP4E** (in Eclipse IDE for Java and most other packages). Define a
  language server launch for `node /path/to/server.js --stdio`, bound to your content types.

Commands for these clients (`workspace/executeCommand`):

- `pepper.server.refresh`
- `pepper.server.rescan`
- `pepper.server.scanWorkingTree`
- `pepper.server.selectRepository`
- `pepper.server.openInPepper`
- `pepper.server.setStatus [findingId, "IN_PROGRESS" | "RESOLVED" | "OPEN"]`

Packaged plugins with a settings page for JetBrains and Eclipse are phases 2 and 3 of the
spec.
