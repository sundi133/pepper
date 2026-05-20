import * as fs from "fs";
import * as path from "path";
import { buildRepoContextSummary } from "@/lib/llm-repo-context";
import {
  FILE_EXTENSIONS,
  SKIP_DIRECTORIES,
  BINARY_EXTENSIONS,
  LLM_MAX_FILE_SIZE_BYTES,
} from "@/lib/constants";

export type FileRole =
  | "route"
  | "controller"
  | "service"
  | "model"
  | "middleware"
  | "auth"
  | "config"
  | "test"
  | "unknown";

export interface RouteEntry {
  method: string;
  path: string;
  filePath: string;
  line: number;
  handler?: string;
}

export interface SinkCandidate {
  kind: string;
  filePath: string;
  line: number;
  symbol?: string;
}

export interface AuthBoundary {
  filePath: string;
  line: number;
  kind: "auth" | "authz" | "guard" | "middleware";
  detail: string;
}

export interface RepoAnalysisContext {
  summary: string;
  frameworks: string[];
  routes: RouteEntry[];
  authBoundaries: AuthBoundary[];
  sinkCandidates: SinkCandidate[];
  fileRoles: Map<string, FileRole>;
  importGraph: Map<string, string[]>;
}

const ROUTE_PATTERNS: Array<{
  re: RegExp;
  method: (m: RegExpMatchArray) => string;
  path: (m: RegExpMatchArray) => string;
}> = [
  {
    re: /\.(?:get|post|put|patch|delete|all)\s*\(\s*['"`]([^'"`]+)['"`]/gi,
    method: (m) => m[0].match(/\.(\w+)/i)?.[1]?.toUpperCase() || "GET",
    path: (m) => m[1],
  },
  {
    re: /@(?:Get|Post|Put|Patch|Delete|Route)\s*\(\s*['"`]([^'"`]+)['"`]/gi,
    method: (m) => m[0].replace("@", "").replace(/\(.*$/, "").toUpperCase(),
    path: (m) => m[1],
  },
  {
    re: /path\s*\(\s*['"`]([^'"`]+)['"`]/gi,
    method: () => "ANY",
    path: (m) => m[1],
  },
  {
    re: /router\.(?:get|post|put|patch|delete)\s*\(\s*['"`]([^'"`]+)['"`]/gi,
    method: (m) => m[0].match(/\.(\w+)/i)?.[1]?.toUpperCase() || "GET",
    path: (m) => m[1],
  },
];

const SINK_PATTERNS: Array<{ kind: string; re: RegExp }> = [
  { kind: "sql", re: /\b(?:query|execute|raw)\s*\(/i },
  { kind: "exec", re: /\b(?:exec|spawn|system|popen|subprocess)\s*\(/i },
  { kind: "eval", re: /\b(?:eval|Function\s*\(|pickle\.loads|yaml\.load\s*\()/i },
  { kind: "file", re: /\b(?:readFile|writeFile|open|send_file|read_bytes)\s*\(/i },
  { kind: "http", re: /\b(?:fetch|axios|request|http\.get|urllib)\s*\(/i },
  { kind: "deserialize", re: /\b(?:deserialize|unserialize|JSON\.parse|marshal\.loads)\s*\(/i },
];

const AUTH_PATTERNS: Array<{ kind: AuthBoundary["kind"]; re: RegExp }> = [
  { kind: "auth", re: /\b(?:authenticate|login|jwt|passport|session)\b/i },
  { kind: "authz", re: /\b(?:authorize|permission|role|acl|policy|guard)\b/i },
  { kind: "guard", re: /@(?:UseGuards|PreAuthorize|login_required|authenticated)/i },
  { kind: "middleware", re: /\b(?:middleware|interceptor)\b/i },
];

function classifyFileRole(filePath: string): FileRole {
  const lower = filePath.toLowerCase();
  if (TEST_PATH.test(lower)) return "test";
  if (/(?:route|router|urls|endpoints)/.test(lower)) return "route";
  if (/(?:controller|handler|api)/.test(lower)) return "controller";
  if (/(?:service|usecase|manager)/.test(lower)) return "service";
  if (/(?:model|entity|schema|dto)/.test(lower)) return "model";
  if (/(?:middleware|guard|filter)/.test(lower)) return "middleware";
  if (/(?:auth|security|oauth)/.test(lower)) return "auth";
  if (/(?:config|settings|env)/.test(lower)) return "config";
  return "unknown";
}

const TEST_PATH =
  /(?:^|\/)(?:test|tests|spec|specs|__tests__|fixtures?|mocks?|examples?|demo|sample)(?:\/|$)|\.(?:test|spec)\.[jt]sx?$/i;

function detectFrameworks(fileList: string[], contents: Map<string, string>): string[] {
  const frameworks = new Set<string>();
  const all = [...contents.values(), fileList.join("\n")].join("\n").toLowerCase();
  if (all.includes("next/") || all.includes("next.config")) frameworks.add("Next.js");
  if (all.includes("express")) frameworks.add("Express");
  if (all.includes("fastapi")) frameworks.add("FastAPI");
  if (all.includes("django")) frameworks.add("Django");
  if (all.includes("spring")) frameworks.add("Spring");
  if (all.includes("nestjs") || all.includes("@nestjs")) frameworks.add("NestJS");
  if (all.includes("graphql")) frameworks.add("GraphQL");
  if (all.includes("grpc")) frameworks.add("gRPC");
  if (all.includes("langchain") || all.includes("openai")) frameworks.add("LLM/AI");
  return [...frameworks];
}

function extractImports(content: string): string[] {
  const imports: string[] = [];
  const patterns = [
    /import\s+.*?from\s+['"]([^'"]+)['"]/g,
    /require\s*\(\s*['"]([^'"]+)['"]\s*\)/g,
    /^import\s+([^\s]+)/gm,
    /^from\s+([^\s]+)\s+import/gm,
  ];
  for (const re of patterns) {
    let m: RegExpExecArray | null;
    while ((m = re.exec(content)) !== null) {
      imports.push(m[1]);
    }
  }
  return imports;
}

export function buildDeepRepoContext(
  workDir: string,
  fileList: string[],
  maxFiles = 120,
): RepoAnalysisContext {
  const routes: RouteEntry[] = [];
  const authBoundaries: AuthBoundary[] = [];
  const sinkCandidates: SinkCandidate[] = [];
  const fileRoles = new Map<string, FileRole>();
  const importGraph = new Map<string, string[]>();
  const contents = new Map<string, string>();

  const scannable = fileList
    .filter((fp) => {
      const ext = path.extname(fp).toLowerCase();
      if (BINARY_EXTENSIONS.has(ext)) return false;
      if (!FILE_EXTENSIONS[ext] && !fp.toLowerCase().includes("dockerfile")) return false;
      return !fp.split(path.sep).some((p) => SKIP_DIRECTORIES.has(p));
    })
    .slice(0, maxFiles);

  for (const filePath of scannable) {
    fileRoles.set(filePath, classifyFileRole(filePath));
    try {
      const full = path.join(workDir, filePath);
      const stat = fs.statSync(full);
      if (stat.size > LLM_MAX_FILE_SIZE_BYTES) continue;
      const content = fs.readFileSync(full, "utf-8");
      contents.set(filePath, content);
      importGraph.set(filePath, extractImports(content));

      const lines = content.split("\n");
      for (let i = 0; i < lines.length; i++) {
        const line = lines[i];
        const lineNum = i + 1;

        for (const rp of ROUTE_PATTERNS) {
          rp.re.lastIndex = 0;
          let m: RegExpExecArray | null;
          while ((m = rp.re.exec(line)) !== null) {
            routes.push({
              method: rp.method(m),
              path: rp.path(m),
              filePath,
              line: lineNum,
            });
          }
        }

        for (const sp of SINK_PATTERNS) {
          if (sp.re.test(line)) {
            sinkCandidates.push({
              kind: sp.kind,
              filePath,
              line: lineNum,
              symbol: line.trim().slice(0, 80),
            });
          }
        }

        for (const ap of AUTH_PATTERNS) {
          if (ap.re.test(line)) {
            authBoundaries.push({
              filePath,
              line: lineNum,
              kind: ap.kind,
              detail: line.trim().slice(0, 120),
            });
          }
        }
      }
    } catch {
      continue;
    }
  }

  const frameworks = detectFrameworks(fileList, contents);
  const summary = buildRepoContextSummary(fileList);
  const contextBlock = formatContextBlock({
    summary,
    frameworks,
    routes: routes.slice(0, 80),
    authBoundaries: authBoundaries.slice(0, 60),
    sinkCandidates: sinkCandidates.slice(0, 80),
    fileRoles,
  });

  return {
    summary: contextBlock,
    frameworks,
    routes,
    authBoundaries,
    sinkCandidates,
    fileRoles,
    importGraph,
  };
}

function formatContextBlock(ctx: {
  summary: string;
  frameworks: string[];
  routes: RouteEntry[];
  authBoundaries: AuthBoundary[];
  sinkCandidates: SinkCandidate[];
  fileRoles: Map<string, FileRole>;
}): string {
  let out = ctx.summary + "\n";
  if (ctx.frameworks.length) {
    out += `\nDETECTED FRAMEWORKS: ${ctx.frameworks.join(", ")}\n`;
  }
  if (ctx.routes.length) {
    out += `\nROUTE MAP (sample):\n`;
    for (const r of ctx.routes.slice(0, 40)) {
      out += `  ${r.method} ${r.path} → ${r.filePath}:${r.line}\n`;
    }
  }
  if (ctx.authBoundaries.length) {
    out += `\nAUTH/AUTHZ BOUNDARIES (sample):\n`;
    for (const a of ctx.authBoundaries.slice(0, 30)) {
      out += `  [${a.kind}] ${a.filePath}:${a.line} ${a.detail}\n`;
    }
  }
  if (ctx.sinkCandidates.length) {
    out += `\nSINK CANDIDATES (sample):\n`;
    for (const s of ctx.sinkCandidates.slice(0, 30)) {
      out += `  [${s.kind}] ${s.filePath}:${s.line}\n`;
    }
  }
  const roles = [...ctx.fileRoles.entries()]
    .filter(([, r]) => r !== "unknown")
    .slice(0, 40);
  if (roles.length) {
    out += `\nFILE ROLES (sample):\n`;
    for (const [fp, role] of roles) {
      out += `  ${role}: ${fp}\n`;
    }
  }
  return out.slice(0, 12000);
}
