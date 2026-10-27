import * as fs from "fs";
import * as path from "path";
import { buildRepoContextSummary } from "@/lib/llm-repo-context";
import {
  FILE_EXTENSIONS,
  SKIP_DIRECTORIES,
  BINARY_EXTENSIONS,
  LLM_MAX_FILE_SIZE_BYTES,
} from "@/lib/constants";
import { llmExcludedPath } from "@/lib/llm-exclusions";

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
  // Flask / FastAPI / Sanic / Quart blueprints: @app.route("/x"), @router.post("/x")
  {
    re: /@\w+\.(route|get|post|put|patch|delete|api_route|websocket)\s*\(\s*['"]([^'"]+)['"]/gi,
    method: (m) => (/^route|api_route$/i.test(m[1]) ? "ANY" : m[1].toUpperCase()),
    path: (m) => m[2],
  },
  // Spring MVC/WebFlux: @GetMapping("/x"), @RequestMapping(value = "/x")
  {
    re: /@(Get|Post|Put|Patch|Delete|Request)Mapping\s*\(\s*(?:(?:value|path)\s*=\s*)?\{?\s*"([^"]+)"/g,
    method: (m) => (m[1] === "Request" ? "ANY" : m[1].toUpperCase()),
    path: (m) => m[2],
  },
  // JAX-RS / Micronaut / Quarkus: @Path("/x")
  {
    re: /@Path\s*\(\s*"([^"]+)"/g,
    method: () => "ANY",
    path: (m) => m[1],
  },
  // ASP.NET Core attributes: [HttpGet("x")], [Route("x")]
  {
    re: /\[(Http(?:Get|Post|Put|Patch|Delete)|Route)\s*\(\s*"([^"]*)"/g,
    method: (m) => (m[1] === "Route" ? "ANY" : m[1].replace("Http", "").toUpperCase()),
    path: (m) => m[2],
  },
  // ASP.NET minimal APIs: app.MapGet("/x", …)
  {
    re: /\.Map(Get|Post|Put|Patch|Delete|Methods)\s*\(\s*"([^"]+)"/g,
    method: (m) => (m[1] === "Methods" ? "ANY" : m[1].toUpperCase()),
    path: (m) => m[2],
  },
  // Laravel / Slim / Lumen: Route::get('/x', …)
  {
    re: /Route::(get|post|put|patch|delete|any|match|resource)\s*\(\s*['"]([^'"]+)['"]/gi,
    method: (m) => (/^(any|match|resource)$/i.test(m[1]) ? "ANY" : m[1].toUpperCase()),
    path: (m) => m[2],
  },
  // PHP 8 attributes (Symfony): #[Route('/x')]
  {
    re: /#\[Route\s*\(\s*['"]([^'"]+)['"]/g,
    method: () => "ANY",
    path: (m) => m[1],
  },
  // Rust Actix / Rocket attributes: #[get("/x")]
  {
    re: /#\[(get|post|put|patch|delete)\s*\(\s*"([^"]+)"/gi,
    method: (m) => m[1].toUpperCase(),
    path: (m) => m[2],
  },
  // Rails / Sinatra / Phoenix / Ktor / Roda DSL at line start: get "/x", post '/x' do
  {
    re: /^\s*(get|post|put|patch|delete)\s*\(?\s*['"]([^'"]+)['"]/gim,
    method: (m) => m[1].toUpperCase(),
    path: (m) => m[2],
  },
  // Go net/http and gorilla/mux: http.HandleFunc("/x", …), r.Handle("/x", …)
  {
    re: /\.Handle(?:Func)?\s*\(\s*"([^"]+)"/g,
    method: () => "ANY",
    path: (m) => m[1],
  },
  // Django legacy url() / re_path()
  {
    re: /\b(?:url|re_path)\s*\(\s*r?['"]([^'"]+)['"]/g,
    method: () => "ANY",
    path: (m) => m[1],
  },
];

const SINK_PATTERNS: Array<{ kind: string; re: RegExp }> = [
  {
    kind: "sql",
    re: /\b(?:query|execute|raw|executeQuery|executeUpdate|createQuery|createNativeQuery|FromSqlRaw|ExecuteSqlRaw|SqlCommand|mysqli_query|mysql_query|pg_query|find_by_sql|whereRaw|selectRaw|orderByRaw|DB::raw|DB::(?:select|statement|insert|update|delete|unprepared)|rawQuery|execSQL|Database\.query|queryRaw|queryRawUnsafe|\$queryRawUnsafe|\$executeRawUnsafe)\s*\(/i,
  },
  {
    kind: "exec",
    re: /\b(?:exec|execSync|spawn|system|popen|subprocess\.\w+|os\.system|shell_exec|passthru|proc_open|Runtime\.getRuntime\(\)\.exec|ProcessBuilder|Process\.Start|exec\.Command|Command::new|os\.execute|Invoke-Expression|IEx|:os\.cmd|System\.cmd)\s*\(/i,
  },
  {
    kind: "eval",
    re: /\b(?:eval|Function\s*\(|pickle\.loads|yaml\.load\s*\(|vm\.runIn(?:Context|NewContext|ThisContext)|instance_eval|class_eval|module_eval|loadstring|Eval\.me|ScriptEngine\w*\.eval|SpelExpressionParser|OgnlUtil|create_function)\s*\(/i,
  },
  {
    kind: "file",
    re: /\b(?:readFile|writeFile|createReadStream|open|send_file|sendFile|read_bytes|fopen|file_get_contents|file_put_contents|include|require_once|FileInputStream|FileOutputStream|Files\.(?:read\w*|write\w*|newInputStream)|File\.(?:Read\w*|Write\w*|Open\w*)|os\.Open|ioutil\.ReadFile|os\.ReadFile|send_data)\s*\(/i,
  },
  {
    kind: "http",
    re: /\b(?:fetch|axios(?:\.\w+)?|request|http\.get|https\.get|urllib\.request\.urlopen|urlopen|requests\.(?:get|post|put|request)|httpx\.\w+|http\.(?:Get|Post|NewRequest)|curl_exec|curl_init|RestTemplate\.\w+|WebClient\.\w+|HttpClient\.\w+|Net::HTTP\.\w+|URI\.open|HTTPoison\.\w+)\s*\(/i,
  },
  {
    kind: "deserialize",
    re: /\b(?:deserialize|unserialize|marshal\.loads|Marshal\.load|ObjectInputStream|readObject|XMLDecoder|BinaryFormatter|NetDataContractSerializer|LosFormatter|TypeNameHandling|jsonpickle\.decode|dill\.loads|:erlang\.binary_to_term)\b/i,
  },
  {
    kind: "xxe",
    re: /\b(?:DocumentBuilderFactory|SAXParserFactory|XMLInputFactory|XmlReader\.Create|XmlDocument|libxml_disable_entity_loader|etree\.(?:parse|fromstring)|lxml\.etree|simplexml_load_string|Nokogiri::XML)\b/i,
  },
  {
    kind: "redirect",
    re: /\b(?:res\.redirect|redirect_to|Response\.Redirect|sendRedirect|RedirectResult|redirect\s*\()|header\s*\(\s*['"]Location/i,
  },
  {
    kind: "dom-xss",
    re: /\.(?:innerHTML|outerHTML|insertAdjacentHTML)\s*[=(]|dangerouslySetInnerHTML\s*=\s*\{|\bv-html\s*=|\{@html\b|\[innerHTML\]\s*=|bypassSecurityTrust\w+\s*\(|document\.write\s*\(/i,
  },
  {
    kind: "template",
    re: /\b(?:render|compile|template|render_template_string|Template\s*\()\s*\(|\.render\s*\(|\|\s*safe\b|mark_safe\s*\(|\.html_safe\b|\braw\s*\(|\{!!|<%-|Html\.Raw\s*\(|\{\{\{/i,
  },
  { kind: "nosql", re: /\$where\s*:|collection\.find\s*\(\s*\{[^}]*\$where|\.aggregate\s*\(\s*\[\s*\{\s*\$(?:function|accumulator)/i },
  { kind: "ldap", re: /\b(?:ldap_search|DirectorySearcher|search_s|InitialDirContext|ldapjs)\b/i },
  { kind: "contract", re: /\b(?:delegatecall|selfdestruct|tx\.origin|\.call\{value|\.call\.value)\b/i },
];

const AUTH_PATTERNS: Array<{ kind: AuthBoundary["kind"]; re: RegExp }> = [
  { kind: "auth", re: /\b(?:authenticate|login|jwt|passport|session|requireAuth|ensureAuthenticated|isAuthenticated|currentUser|current_user|getServerSession|auth\(\))\b/i },
  { kind: "authz", re: /\b(?:authorize!?|permission|role|acl|policy|guard|can\?|cannot\?|Gate::\w+|abilities|hasRole|hasAuthority|checkPermission)\b/i },
  {
    kind: "guard",
    re: /@(?:UseGuards|PreAuthorize|PostAuthorize|Secured|RolesAllowed|PermitAll|DenyAll|login_required|permission_required|user_passes_test|authenticated|requires_auth|jwt_required)\b|\[(?:Authorize|AllowAnonymous)\b|\bbefore_action\s+:authenticate|\bpermission_classes\s*=|\bcanActivate\b|\bmiddleware\s*\(\s*['"]auth/i,
  },
  { kind: "middleware", re: /\b(?:middleware|interceptor|filter_chain|SecurityFilterChain|before_request|plug\s+:)\b/i },
];

const TEST_PATH =
  /(?:^|\/)(?:test|tests|spec|specs|__tests__|fixtures?|mocks?|examples?|demo|sample)(?:\/|$)|\.(?:test|spec)\.[jt]sx?$/i;

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

/**
 * Framework signals: an import/package name or a framework-only file or API,
 * never a bare word ("express" alone matches "expression", "spring" a comment).
 * `paths` is tested against the file list, `code` against file contents.
 */
const FRAMEWORK_SIGNALS: Array<{ name: string; paths?: RegExp; code?: RegExp }> = [
  // JavaScript / TypeScript back end
  { name: "Express", code: /(?:require\(\s*|from\s+)['"]express['"]/ },
  { name: "NestJS", code: /from\s+['"]@nestjs\// },
  { name: "Fastify", code: /(?:require\(\s*|from\s+)['"]fastify['"]/ },
  { name: "Koa", code: /(?:require\(\s*|from\s+)['"]koa['"]/ },
  { name: "Hapi", code: /(?:require\(\s*|from\s+)['"]@hapi\/hapi['"]/ },
  { name: "Hono", code: /from\s+['"]hono['"]/ },
  { name: "Next.js", paths: /(?:^|\/)next\.config\.(?:js|mjs|ts)$/, code: /from\s+['"]next\// },
  { name: "Nuxt", paths: /(?:^|\/)nuxt\.config\.(?:js|ts)$/ },
  { name: "Remix", code: /from\s+['"]@remix-run\// },
  { name: "SvelteKit", paths: /(?:^|\/)svelte\.config\.js$/, code: /from\s+['"]@sveltejs\/kit/ },
  { name: "Astro", paths: /\.astro$/ },
  // JavaScript / TypeScript front end
  { name: "React", code: /from\s+['"]react['"]/ },
  { name: "Angular", code: /from\s+['"]@angular\/core['"]/ },
  { name: "Vue", paths: /\.vue$/, code: /from\s+['"]vue['"]/ },
  { name: "Svelte", paths: /\.svelte$/ },
  // Python
  { name: "Django", paths: /(?:^|\/)manage\.py$|(?:^|\/)settings\.py$/, code: /from\s+django[.\s]/ },
  { name: "Flask", code: /from\s+flask\s+import|import\s+flask\b/ },
  { name: "FastAPI", code: /from\s+fastapi\s+import/ },
  { name: "Starlette", code: /from\s+starlette[.\s]/ },
  { name: "Tornado", code: /import\s+tornado\b|from\s+tornado[.\s]/ },
  { name: "Pyramid", code: /from\s+pyramid[.\s]/ },
  { name: "aiohttp", code: /from\s+aiohttp\s+import\s+web|aiohttp\.web/ },
  // JVM
  { name: "Spring", code: /import\s+org\.springframework\./ },
  { name: "Jakarta EE / JAX-RS", code: /import\s+(?:javax|jakarta)\.ws\.rs\./ },
  { name: "Java Servlet", code: /import\s+(?:javax|jakarta)\.servlet\./ },
  { name: "Struts", code: /import\s+org\.apache\.struts2?\./ },
  { name: "Micronaut", code: /import\s+io\.micronaut\./ },
  { name: "Quarkus", code: /import\s+io\.quarkus\./ },
  { name: "Play", code: /import\s+play\.api\.|import\s+play\.mvc\./ },
  { name: "Ktor", code: /import\s+io\.ktor\./ },
  { name: "Grails", paths: /grails-app\// },
  { name: "Android", paths: /(?:^|\/)AndroidManifest\.xml$/, code: /import\s+android\./ },
  // .NET
  { name: "ASP.NET Core", code: /using\s+Microsoft\.AspNetCore\./ },
  { name: "ASP.NET Web Forms / MVC", paths: /\.(?:aspx|ascx|cshtml)$/, code: /using\s+System\.Web\b/ },
  { name: "Blazor", paths: /\.razor$/ },
  // PHP
  { name: "Laravel", paths: /(?:^|\/)artisan$/, code: /use\s+Illuminate\\/ },
  { name: "Symfony", code: /use\s+Symfony\\/ },
  { name: "WordPress", paths: /wp-content\/|wp-config\.php$/ },
  { name: "Drupal", paths: /\.module$|(?:^|\/)core\/lib\/Drupal/ },
  { name: "CodeIgniter", code: /CodeIgniter\\|defined\(\s*'BASEPATH'\s*\)/ },
  { name: "Slim", code: /use\s+Slim\\/ },
  // Ruby
  { name: "Rails", paths: /(?:^|\/)config\/routes\.rb$|(?:^|\/)app\/controllers\// },
  { name: "Sinatra", code: /require\s+['"]sinatra['"]/ },
  // Go
  { name: "Gin", code: /"github\.com\/gin-gonic\/gin"/ },
  { name: "Echo", code: /"github\.com\/labstack\/echo/ },
  { name: "Fiber", code: /"github\.com\/gofiber\/fiber/ },
  { name: "Chi", code: /"github\.com\/go-chi\/chi/ },
  { name: "Gorilla Mux", code: /"github\.com\/gorilla\/mux"/ },
  // Rust
  { name: "Actix Web", code: /use\s+actix_web\b/ },
  { name: "Axum", code: /use\s+axum\b/ },
  { name: "Rocket", code: /use\s+rocket\b|#\[macro_use\]\s*extern\s+crate\s+rocket/ },
  // Elixir / mobile / other
  { name: "Phoenix", code: /use\s+Phoenix\.|use\s+\w+Web,\s*:controller/ },
  { name: "Flutter", code: /import\s+['"]package:flutter\// },
  { name: "SwiftUI / iOS", code: /import\s+(?:SwiftUI|UIKit)\b/ },
  { name: "Salesforce Apex", paths: /\.(?:cls|trigger)$/, code: /\b(?:with|without)\s+sharing\b/ },
  { name: "Solidity", paths: /\.sol$/ },
  // Cross-cutting
  { name: "GraphQL", code: /from\s+['"](?:graphql|@apollo\/server|apollo-server[\w-]*|type-graphql|@nestjs\/graphql)['"]|import\s+graphene|import\s+strawberry/ },
  { name: "gRPC", paths: /\.proto$/, code: /@grpc\/grpc-js|import\s+grpc\b|google\.golang\.org\/grpc/ },
  { name: "LLM/AI", code: /from\s+['"](?:openai|@anthropic-ai\/sdk|langchain|@langchain\/[\w-]+|ai)['"]|import\s+(?:openai|anthropic|langchain)\b|from\s+(?:openai|anthropic|langchain)\s+import/ },
];

function detectFrameworks(fileList: string[], contents: Map<string, string>): string[] {
  const paths = fileList.map((p) => p.split(path.sep).join("/"));
  const frameworks: string[] = [];
  for (const signal of FRAMEWORK_SIGNALS) {
    const byPath = signal.paths && paths.some((p) => signal.paths!.test(p));
    let byCode = false;
    if (!byPath && signal.code) {
      for (const text of contents.values()) {
        if (signal.code.test(text)) {
          byCode = true;
          break;
        }
      }
    }
    if (byPath || byCode) frameworks.push(signal.name);
  }
  return frameworks;
}

function extractImports(content: string): string[] {
  const imports: string[] = [];
  const patterns = [
    // JS/TS
    /import\s+.*?from\s+['"]([^'"]+)['"]/g,
    /require\s*\(\s*['"]([^'"]+)['"]\s*\)/g,
    // Python, Java, Kotlin, Scala, Swift, Dart, Haskell
    /^import\s+([^\s;]+)/gm,
    /^from\s+([^\s]+)\s+import/gm,
    // Go: import "x" and the lines of an import ( … ) block
    /^\s*(?:import\s+)?(?:\w+\s+)?"([\w./-]+)"\s*$/gm,
    // PHP use / include, C# using, Rust use, Elixir alias/import/use
    /^\s*use\s+([\w\\:.]+)/gm,
    /^\s*(?:include|require)(?:_once)?\s*\(?\s*['"]([^'"]+)['"]/gm,
    /^\s*using\s+(?:static\s+)?([\w.]+)\s*;/gm,
    /^\s*(?:alias|import)\s+([A-Z][\w.]+)/gm,
    // Ruby, Perl, Lua
    /^\s*require(?:_relative)?\s+['"]([^'"]+)['"]/gm,
    /^\s*(?:local\s+\w+\s*=\s*)?require\s*\(?\s*['"]([^'"]+)['"]/gm,
    // C / C++ local headers
    /^\s*#\s*include\s+"([^"]+)"/gm,
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
  maxFiles = 300,
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
    // Excluded files keep their role (the path isn't sensitive) but not their content.
    if (llmExcludedPath(filePath)) continue;
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
          sp.re.lastIndex = 0;
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
          ap.re.lastIndex = 0;
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
