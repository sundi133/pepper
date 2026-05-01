import * as fs from "fs";
import * as path from "path";

/**
 * Heuristic repository architecture summary for SAST reporting (routes, stack hints).
 * Does not execute code — safe static inspection only.
 */

export interface DetectedRoute {
  /** Normalized POSIX-style path segment, e.g. /api/users/[id] */
  pattern: string;
  method?: string;
  filePath: string;
}

export interface ArchitectureSummary {
  languagesPresent: string[];
  frameworks: string[];
  backendPatterns: string[];
  frontendPatterns: string[];
  routeHints: DetectedRoute[];
  configFiles: string[];
  authHints: string[];
  dataStores: string[];
  notes: string[];
}

function safeReadJson(filePath: string): unknown | null {
  try {
    return JSON.parse(fs.readFileSync(filePath, "utf-8"));
  } catch {
    return null;
  }
}

function detectFrameworksFromPackageJson(
  pkg: Record<string, unknown> | null,
): string[] {
  if (!pkg) return [];
  const deps = {
    ...(typeof pkg.dependencies === "object" && pkg.dependencies
      ? (pkg.dependencies as Record<string, string>)
      : {}),
    ...(typeof pkg.devDependencies === "object" && pkg.devDependencies
      ? (pkg.devDependencies as Record<string, string>)
      : {}),
  };
  const keys = Object.keys(deps);
  const found: string[] = [];
  const map: Array<[RegExp, string]> = [
    [/^next$/i, "Next.js"],
    [/^react$/i, "React"],
    [/^express$/i, "Express"],
    [/^fastify$/i, "Fastify"],
    [/^@nestjs/i, "NestJS"],
    [/^django$/i, "Django"],
    [/^flask$/i, "Flask"],
    [/^fastapi$/i, "FastAPI"],
    [/^spring-boot/i, "Spring Boot"],
    [/^laravel/i, "Laravel"],
    [/^rails$/i, "Ruby on Rails"],
    [/^gin-gonic/i, "Gin"],
    [/^echo$/i, "Echo"],
    [/^angular$/i, "Angular"],
    [/^vue$/i, "Vue"],
    [/^@angular/i, "Angular"],
    [/^svelte/i, "Svelte"],
    [/^prisma$/i, "Prisma"],
    [/^sequelize$/i, "Sequelize"],
    [/^typeorm$/i, "TypeORM"],
    [/^mongoose$/i, "Mongoose"],
  ];
  for (const k of keys) {
    for (const [re, label] of map) {
      if (re.test(k) && !found.includes(label)) found.push(label);
    }
  }
  return found;
}

function extractNextAppRoutes(filePath: string, content: string): DetectedRoute[] {
  const routes: DetectedRoute[] = [];
  const norm = filePath.split(path.sep).join("/");
  if (!norm.includes("/app/") || !/\/(page|route)\.(tsx|ts|jsx|js)$/.test(norm)) {
    return routes;
  }
  const base = norm
    .replace(/^.*?\/app\//, "")
    .replace(/\/(page|route)\.(tsx|ts|jsx|js)$/, "")
    .replace(/^\/?/, "");
  const pattern = "/" + (base ? base.split("/").join("/") : "");
  routes.push({ pattern, filePath: norm, method: norm.includes("route.") ? undefined : "GET" });
  return routes;
}

function extractExpressRoutes(content: string, filePath: string): DetectedRoute[] {
  const routes: DetectedRoute[] = [];
  const re =
    /\.(?:get|post|put|patch|delete|all)\s*\(\s*['"`]([^'"`]+)['"`]/gi;
  let m: RegExpExecArray | null;
  while ((m = re.exec(content)) !== null) {
    routes.push({
      pattern: m[1],
      method: m[0].match(/\.(get|post|put|patch|delete)/i)?.[1]?.toUpperCase(),
      filePath,
    });
  }
  return routes;
}

function extractFlaskRoutes(content: string, filePath: string): DetectedRoute[] {
  const routes: DetectedRoute[] = [];
  const re =
    /@(?:app|bp)\.route\s*\(\s*['"`]([^'"`]+)['"`]/gi;
  let m: RegExpExecArray | null;
  while ((m = re.exec(content)) !== null) {
    routes.push({ pattern: m[1], filePath });
  }
  return routes;
}

export function analyzeArchitecture(
  workDir: string,
  fileList: string[],
): ArchitectureSummary {
  const languages = new Set<string>();
  const frameworks: string[] = [];
  const backendPatterns: string[] = [];
  const frontendPatterns: string[] = [];
  const routeHints: DetectedRoute[] = [];
  const configFiles: string[] = [];
  const authHints: string[] = [];
  const dataStores: string[] = [];
  const notes: string[] = [];

  const pkgPath = path.join(workDir, "package.json");
  if (fs.existsSync(pkgPath)) {
    const pkg = safeReadJson(pkgPath) as Record<string, unknown> | null;
    frameworks.push(...detectFrameworksFromPackageJson(pkg));
    configFiles.push("package.json");
    if (frameworks.some((f) => ["Next.js", "React"].includes(f))) {
      frontendPatterns.push("Node/React ecosystem");
    }
    if (frameworks.some((f) => ["Express", "Fastify", "NestJS"].includes(f))) {
      backendPatterns.push("Node HTTP server");
    }
  }

  const reqPath = path.join(workDir, "requirements.txt");
  if (fs.existsSync(reqPath)) {
    configFiles.push("requirements.txt");
    const txt = fs.readFileSync(reqPath, "utf-8");
    if (/django/i.test(txt)) frameworks.push("Django");
    if (/flask/i.test(txt)) frameworks.push("Flask");
    if (/fastapi/i.test(txt)) frameworks.push("FastAPI");
    backendPatterns.push("Python");
    languages.add("python");
  }

  const goMod = fileList.find((f) => f.endsWith("go.mod"));
  if (goMod) {
    backendPatterns.push("Go modules");
    languages.add("go");
  }

  const pom = fileList.find((f) => f.endsWith("pom.xml"));
  if (pom) {
    backendPatterns.push("Maven/Java");
    languages.add("java");
  }

  for (const rel of fileList) {
    const ext = path.extname(rel).toLowerCase();
    if ([".ts", ".tsx", ".js", ".jsx"].includes(ext)) {
      languages.add("javascript");
    }
    if (ext === ".py") languages.add("python");
    if (ext === ".go") languages.add("go");
    if (ext === ".java") languages.add("java");
    if (ext === ".php") languages.add("php");
    if (ext === ".rb") languages.add("ruby");

    if (rel.endsWith("prisma/schema.prisma")) {
      dataStores.push("Prisma ORM");
      configFiles.push(rel);
    }
    if (rel.match(/docker-compose\.ya?ml$/i)) configFiles.push(rel);
    if (rel.endsWith(".env.example")) configFiles.push(rel);

    const full = path.join(workDir, rel);
    let content: string;
    try {
      if (fs.statSync(full).size > 512_000) continue;
      content = fs.readFileSync(full, "utf-8");
    } catch {
      continue;
    }

    if (
      /nextauth|NextAuth|passport\.authenticate|@auth|jwt\.verify|bcrypt|argon2/i.test(
        content,
      )
    ) {
      authHints.push(`Auth-related symbols in ${rel}`);
    }
    if (/mongoose\.connect|createConnection|sequelize|typeorm|PrismaClient/i.test(content)) {
      dataStores.push(`DB API usage in ${rel}`);
    }

    routeHints.push(...extractNextAppRoutes(rel, content));
    routeHints.push(...extractExpressRoutes(content, rel));
    routeHints.push(...extractFlaskRoutes(content, rel));
  }

  if (frameworks.length === 0 && languages.size > 0) {
    notes.push("No primary web framework detected from manifests; route mapping is file-heuristic only.");
  }

  return {
    languagesPresent: [...languages],
    frameworks: [...new Set(frameworks)],
    backendPatterns: [...new Set(backendPatterns)],
    frontendPatterns: [...new Set(frontendPatterns)],
    routeHints: dedupeRoutes(routeHints),
    configFiles: [...new Set(configFiles)].slice(0, 80),
    authHints: [...new Set(authHints)].slice(0, 40),
    dataStores: [...new Set(dataStores)].slice(0, 40),
    notes,
  };
}

function dedupeRoutes(routes: DetectedRoute[]): DetectedRoute[] {
  const seen = new Set<string>();
  const out: DetectedRoute[] = [];
  for (const r of routes) {
    const k = `${r.pattern}|${r.filePath}|${r.method || ""}`;
    if (seen.has(k)) continue;
    seen.add(k);
    out.push(r);
  }
  return out.slice(0, 200);
}

/** Match a source file to the best-known HTTP route pattern (heuristic). */
export function matchRouteForFile(
  filePath: string,
  arch: ArchitectureSummary,
): DetectedRoute | undefined {
  const norm = filePath.replace(/\\/g, "/");
  const exact = arch.routeHints.filter((r) => r.filePath === norm);
  if (exact.length) return exact[0];
  const base = norm.split("/").pop() || "";
  return arch.routeHints.find((r) => r.filePath.endsWith(base));
}

export function architectureOverviewMarkdown(a: ArchitectureSummary): string {
  const lines: string[] = [];
  lines.push(
    `- **Languages observed:** ${a.languagesPresent.length ? a.languagesPresent.join(", ") : "Unknown"}`,
  );
  lines.push(
    `- **Frameworks / libs (from manifests):** ${a.frameworks.length ? a.frameworks.join(", ") : "None detected"}`,
  );
  if (a.backendPatterns.length) {
    lines.push(`- **Backend patterns:** ${a.backendPatterns.join(", ")}`);
  }
  if (a.configFiles.length) {
    lines.push(`- **Notable config:** ${a.configFiles.slice(0, 12).join(", ")}${a.configFiles.length > 12 ? "…" : ""}`);
  }
  if (a.routeHints.length) {
    lines.push(
      `- **Inferred routes (sample):** ${a.routeHints
        .slice(0, 8)
        .map((r) => `${r.pattern}${r.method ? ` [${r.method}]` : ""}`)
        .join("; ")}`,
    );
  }
  if (a.notes.length) lines.push(`- **Notes:** ${a.notes.join(" ")}`);
  return lines.join("\n");
}
