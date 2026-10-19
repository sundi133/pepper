// Bundles the extension client and the Pepper language server into dist/.
import { build } from "esbuild";

const common = { bundle: true, platform: "node", target: "node18", format: "cjs", sourcemap: true, minify: true, logLevel: "info" };

await build({ ...common, entryPoints: ["src/extension.ts"], outfile: "dist/extension.js", external: ["vscode"] });
await build({ ...common, entryPoints: ["../pepper-lsp/src/server.ts"], outfile: "dist/server.js" });
