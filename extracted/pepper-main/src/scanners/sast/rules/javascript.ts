import { PatternRule } from "../../types";

export const javascriptRules: PatternRule[] = [
  {
    id: "JS-EVAL-001",
    title: "Use of eval()",
    description:
      "eval() executes arbitrary code and can lead to code injection if user input is involved. Use safer alternatives like JSON.parse() for data parsing.",
    severity: "HIGH",
    cweId: "CWE-95",
    languages: ["javascript", "typescript"],
    pattern: /\beval\s*\(/,
    negative: /\/\/.*eval|\/\*.*eval/,
  },
  {
    id: "JS-XSS-001",
    title: "dangerouslySetInnerHTML usage",
    description:
      "React's dangerouslySetInnerHTML can lead to XSS if the HTML content is not properly sanitized. Use DOMPurify or similar libraries to sanitize input.",
    severity: "MEDIUM",
    cweId: "CWE-79",
    languages: ["javascript", "typescript"],
    pattern: /dangerouslySetInnerHTML/,
  },
  {
    id: "JS-XSS-002",
    title: "Direct innerHTML assignment",
    description:
      "Setting innerHTML directly can lead to XSS vulnerabilities. Use textContent for plain text or sanitize HTML before insertion.",
    severity: "MEDIUM",
    cweId: "CWE-79",
    languages: ["javascript", "typescript"],
    pattern: /\.innerHTML\s*[=+]/,
  },
  {
    id: "JS-SQL-001",
    title: "SQL query with string concatenation",
    description:
      "Building SQL queries with string concatenation is vulnerable to SQL injection. Use parameterized queries or prepared statements instead.",
    severity: "HIGH",
    cweId: "CWE-89",
    languages: ["javascript", "typescript"],
    pattern:
      /(?:query|execute|exec)\s*\(\s*['"`](?:SELECT|INSERT|UPDATE|DELETE|DROP).*\+/i,
  },
  {
    id: "JS-SQL-002",
    title: "SQL template literal without parameterization",
    description:
      "SQL queries using template literals with embedded expressions are vulnerable to SQL injection. Use parameterized queries.",
    severity: "HIGH",
    cweId: "CWE-89",
    languages: ["javascript", "typescript"],
    pattern:
      /(?:query|execute|exec)\s*\(\s*`(?:SELECT|INSERT|UPDATE|DELETE).*\$\{/i,
  },
  {
    id: "JS-NOSQL-001",
    title: "NoSQL injection via $where",
    description:
      "Using $where in MongoDB queries can lead to NoSQL injection. Use structured query operators instead.",
    severity: "HIGH",
    cweId: "CWE-943",
    languages: ["javascript", "typescript"],
    pattern: /\$where\s*:/,
  },
  {
    id: "JS-PATH-001",
    title: "Potential path traversal",
    description:
      "Constructing file paths with user input without validation can lead to path traversal attacks. Validate and sanitize path inputs.",
    severity: "HIGH",
    cweId: "CWE-22",
    languages: ["javascript", "typescript"],
    pattern:
      /(?:readFile|readFileSync|createReadStream|writeFile|writeFileSync)\s*\([^)]*(?:req\.|params\.|query\.|body\.)/,
  },
  {
    id: "JS-EXEC-001",
    title: "Command injection via child_process",
    description:
      "Using child_process.exec with user-controlled input can lead to command injection. Use execFile with an argument array instead.",
    severity: "CRITICAL",
    cweId: "CWE-78",
    languages: ["javascript", "typescript"],
    pattern: /(?:exec|execSync|spawn|spawnSync)\s*\([^)]*(?:\+|`|\$\{)/,
  },
  {
    id: "JS-PROTO-001",
    title: "Prototype pollution",
    description:
      "Direct access to __proto__ can lead to prototype pollution. Validate object keys before assignment.",
    severity: "HIGH",
    cweId: "CWE-1321",
    languages: ["javascript", "typescript"],
    pattern: /__proto__/,
  },
  {
    id: "JS-CORS-001",
    title: "Permissive CORS policy",
    description:
      "Setting Access-Control-Allow-Origin to '*' allows any domain to make requests. Restrict to specific trusted origins.",
    severity: "MEDIUM",
    cweId: "CWE-942",
    languages: ["javascript", "typescript"],
    pattern: /Access-Control-Allow-Origin['":\s]*['"]\*['"]/,
  },
  {
    id: "JS-CRYPTO-001",
    title: "Math.random() used for security",
    description:
      "Math.random() is not cryptographically secure. Use crypto.randomBytes() or crypto.getRandomValues() for security-sensitive operations.",
    severity: "MEDIUM",
    cweId: "CWE-338",
    languages: ["javascript", "typescript"],
    pattern: /Math\.random\s*\(\)/,
    negative: /(?:test|spec|mock|example|demo)/i,
  },
  {
    id: "JS-DESER-001",
    title: "Unsafe deserialization with node-serialize",
    description:
      "node-serialize.unserialize() can execute arbitrary code. Never deserialize untrusted data.",
    severity: "CRITICAL",
    cweId: "CWE-502",
    languages: ["javascript", "typescript"],
    pattern: /\.unserialize\s*\(/,
  },
  {
    id: "JS-REDIRECT-001",
    title: "Open redirect",
    description:
      "Redirecting to user-supplied URLs without validation can lead to phishing attacks. Validate redirect targets against a whitelist.",
    severity: "MEDIUM",
    cweId: "CWE-601",
    languages: ["javascript", "typescript"],
    pattern:
      /(?:res\.redirect|window\.location|location\.href)\s*[=(]\s*(?:req\.|params\.|query\.)/,
  },
];
