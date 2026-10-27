/**
 * Pure helpers that turn SCA finding data into decisions: what the weakness
 * lets an attacker do, how urgent the fix is, whether the upgrade is breaking,
 * and how to force a patched version of a transitive dependency. Shared by the
 * scanner (stored text) and the finding panel (display), so no I/O here.
 */

export interface CweImpact {
  /** Short attacker outcome, e.g. "Run JavaScript in a victim's session". */
  outcome: string;
  consequences: string[];
}

const IMPACT_BY_CLASS: Array<{ cwes: number[]; match?: RegExp; impact: CweImpact }> = [
  {
    cwes: [79, 80, 83, 87],
    match: /\bxss\b|cross[- ]site scripting/i,
    impact: {
      outcome: "Run attacker JavaScript in a victim's browser session",
      consequences: [
        "Session or token theft and account takeover",
        "Actions performed as the victim (change email, transfer data)",
        "Phishing content served from your own domain",
      ],
    },
  },
  {
    cwes: [89, 564, 943],
    match: /sql injection|nosql injection/i,
    impact: {
      outcome: "Read or change database contents",
      consequences: [
        "Bulk data theft (user records, credentials)",
        "Tampering with or deleting stored data",
        "Authentication bypass through crafted queries",
      ],
    },
  },
  {
    cwes: [77, 78, 94, 95, 96, 917, 1336],
    match: /remote code execution|\brce\b|command injection|code injection|template injection/i,
    impact: {
      outcome: "Execute code on the server",
      consequences: [
        "Full compromise of the application host",
        "Access to secrets, environment variables and connected systems",
        "A foothold for lateral movement",
      ],
    },
  },
  {
    cwes: [502],
    match: /deserializ/i,
    impact: {
      outcome: "Execute code by sending crafted serialized data",
      consequences: [
        "Remote code execution on the server",
        "Bypass of application logic through forged objects",
      ],
    },
  },
  {
    cwes: [1321],
    match: /prototype pollution/i,
    impact: {
      outcome: "Change behavior of every object in the process",
      consequences: [
        "Authorization checks bypassed through polluted properties",
        "Denial of service; code execution in some gadget chains",
      ],
    },
  },
  {
    cwes: [22, 23, 35, 59],
    match: /path traversal|directory traversal|zip slip/i,
    impact: {
      outcome: "Read or write files outside the intended directory",
      consequences: [
        "Disclosure of configuration files and secrets",
        "Overwriting files, sometimes leading to code execution",
      ],
    },
  },
  {
    cwes: [918],
    match: /\bssrf\b|server[- ]side request forgery/i,
    impact: {
      outcome: "Make the server send requests to internal systems",
      consequences: [
        "Access to cloud metadata credentials",
        "Scanning and attacking internal services",
      ],
    },
  },
  {
    cwes: [287, 288, 290, 294, 306, 345, 347, 862, 863, 639],
    match: /authentication bypass|authorization bypass|improper authentication|signature verification/i,
    impact: {
      outcome: "Bypass authentication or authorization",
      consequences: [
        "Access to other users' data or admin functions",
        "Forged tokens or sessions accepted as valid",
      ],
    },
  },
  {
    cwes: [400, 770, 1333, 674, 835, 409],
    match: /denial of service|\bdos\b|redos|resource exhaustion|uncontrolled recursion/i,
    impact: {
      outcome: "Make the application unavailable",
      consequences: [
        "Outage from a single crafted request",
        "Higher infrastructure cost under attack",
      ],
    },
  },
  {
    cwes: [601],
    match: /open redirect/i,
    impact: {
      outcome: "Redirect users to an attacker's site",
      consequences: ["Credible phishing links on your domain", "OAuth token leakage in some flows"],
    },
  },
  {
    cwes: [200, 201, 209, 532, 359],
    match: /information (disclosure|exposure)|sensitive data/i,
    impact: {
      outcome: "Expose sensitive information",
      consequences: ["Leak of internal data, secrets or personal data", "Details that help a follow-up attack"],
    },
  },
  {
    cwes: [327, 328, 326, 330, 338, 295, 297],
    match: /weak (crypto|cipher|hash)|certificate validation|insecure random/i,
    impact: {
      outcome: "Weaken encryption or trust checks",
      consequences: ["Interception or tampering of protected traffic", "Forged or guessable tokens"],
    },
  },
  {
    cwes: [352],
    match: /\bcsrf\b|cross[- ]site request forgery/i,
    impact: {
      outcome: "Make a logged-in user perform unwanted actions",
      consequences: ["State changes on the victim's account without consent"],
    },
  },
  {
    cwes: [444],
    match: /request smuggling/i,
    impact: {
      outcome: "Smuggle requests past proxies",
      consequences: ["Cache poisoning and hijacking other users' requests", "Bypass of front-end security controls"],
    },
  },
];

function cweNumber(cweId: string | null | undefined): number | null {
  const m = cweId?.match(/(\d+)/);
  return m ? Number(m[1]) : null;
}

/**
 * What a weakness lets an attacker do, from its CWE or, failing that, the
 * advisory title. Null when the class isn't recognized.
 */
export function impactForWeakness(
  cweId: string | null | undefined,
  text?: string | null,
): CweImpact | null {
  const n = cweNumber(cweId);
  if (n !== null) {
    const byCwe = IMPACT_BY_CLASS.find((c) => c.cwes.includes(n));
    if (byCwe) return byCwe.impact;
  }
  if (text) {
    const byText = IMPACT_BY_CLASS.find((c) => c.match?.test(text));
    if (byText) return byText.impact;
  }
  return null;
}

export type UpgradeRisk = "patch" | "minor" | "major" | "unknown";

function versionParts(v: string): number[] | null {
  const m = v.trim().replace(/^[v=^~]+/i, "").match(/^(\d+)(?:\.(\d+))?(?:\.(\d+))?/);
  if (!m) return null;
  return [Number(m[1]), Number(m[2] ?? 0), Number(m[3] ?? 0)];
}

/**
 * How big the jump to the fixed version is. A major bump (or a 0.x minor
 * bump, which semver treats as breaking) needs code changes and testing.
 */
export function upgradeRisk(
  current: string | null | undefined,
  fix: string | null | undefined,
): UpgradeRisk {
  if (!current || !fix) return "unknown";
  const a = versionParts(current);
  const b = versionParts(fix);
  if (!a || !b) return "unknown";
  if (b[0] !== a[0]) return "major";
  if (a[0] === 0 && b[1] !== a[1]) return "major";
  if (b[1] !== a[1]) return "minor";
  return "patch";
}

export type ExploitPriority = "act-now" | "prioritize" | "schedule" | "track";

export interface PriorityInput {
  severity: string;
  cvssScore?: number | null;
  epssScore?: number | null;
  cisaKevListed?: boolean | null;
  /** Package is imported somewhere in the scanned source. */
  imported?: boolean | null;
  directDependency?: boolean | null;
}

export interface PriorityVerdict {
  priority: ExploitPriority;
  label: string;
  reasons: string[];
}

const PRIORITY_LABEL: Record<ExploitPriority, string> = {
  "act-now": "Act now",
  prioritize: "Fix this sprint",
  schedule: "Schedule a fix",
  track: "Track",
};

/**
 * Remediation priority from exploitation evidence, not CVSS alone (SSVC
 * style): known exploitation (CISA KEV) beats a high EPSS, which beats a
 * high base score; evidence the package isn't imported lowers urgency.
 */
export function exploitPriority(input: PriorityInput): PriorityVerdict {
  const reasons: string[] = [];
  const sev = input.severity.toUpperCase();
  const epss = input.epssScore ?? null;
  const cvss = input.cvssScore ?? null;

  if (input.cisaKevListed) reasons.push("Exploited in the wild (CISA KEV)");
  if (epss !== null && epss >= 0.1) {
    reasons.push(`${Math.round(epss * 100)}% chance of exploitation in 30 days (EPSS)`);
  }
  if (cvss !== null) reasons.push(`CVSS ${cvss.toFixed(1)}`);
  if (input.imported === false) reasons.push("Package isn't imported in scanned code");
  else if (input.imported) reasons.push("Package is imported in your code");
  if (input.directDependency === false) reasons.push("Transitive dependency");

  let priority: ExploitPriority;
  if (input.cisaKevListed || (epss !== null && epss >= 0.5)) {
    priority = "act-now";
  } else if (sev === "CRITICAL" || (epss !== null && epss >= 0.1) || (sev === "HIGH" && input.imported)) {
    priority = "prioritize";
  } else if (sev === "HIGH" || sev === "MEDIUM") {
    priority = "schedule";
  } else {
    priority = "track";
  }
  // Not imported anywhere: one step down, unless exploitation is known.
  if (input.imported === false && !input.cisaKevListed) {
    priority =
      priority === "act-now" ? "prioritize" : priority === "prioritize" ? "schedule" : priority;
  }
  return { priority, label: PRIORITY_LABEL[priority], reasons };
}

export interface FixGuidance {
  /** One command that applies the fix, when there is one. */
  command?: string;
  /** Config to force a patched transitive version (overrides etc.). */
  override?: { file: string; snippet: string };
  note?: string;
}

/**
 * How to get a patched version in. A direct dependency is upgraded in place;
 * a transitive one is upgraded through the package that pulls it in, or
 * pinned with the ecosystem's override mechanism.
 */
export function fixGuidance(params: {
  ecosystem: string;
  packageName: string;
  fixVersion?: string | null;
  directDependency?: boolean | null;
  introducedBy?: string | null;
}): FixGuidance {
  const { packageName: pkg, fixVersion } = params;
  const eco = params.ecosystem.toLowerCase();
  if (!fixVersion) {
    return {
      note: "No patched version is published yet. Remove or replace the package, or mitigate and record an exception.",
    };
  }
  const transitive = params.directDependency === false;
  const via = params.introducedBy && params.introducedBy !== pkg ? params.introducedBy : null;

  if (eco === "npm" || eco.includes("node") || eco.includes("javascript")) {
    if (!transitive) return { command: `npm install ${pkg}@${fixVersion}` };
    return {
      command: via ? `npm update ${via}` : undefined,
      override: {
        file: "package.json",
        snippet: JSON.stringify({ overrides: { [pkg]: fixVersion } }, null, 2),
      },
      note: via
        ? `${pkg} comes in through ${via}. Update ${via} first; if its latest release still pulls the vulnerable version, add an override (pnpm: "pnpm.overrides", Yarn: "resolutions").`
        : `Add an override (pnpm: "pnpm.overrides", Yarn: "resolutions"), then reinstall to refresh the lockfile.`,
    };
  }
  if (eco === "pypi" || eco.includes("python") || eco.includes("pip")) {
    if (!transitive) return { command: `pip install "${pkg}>=${fixVersion}"` };
    return {
      override: { file: "constraints.txt", snippet: `${pkg}>=${fixVersion}` },
      note: `Install with "pip install -c constraints.txt -r requirements.txt", or add ${pkg}>=${fixVersion} to your Poetry/uv dependencies.`,
    };
  }
  if (eco === "maven" || eco.includes("java")) {
    const [group, artifact] = pkg.includes(":") ? pkg.split(":") : [pkg, pkg];
    return {
      override: {
        file: "pom.xml",
        snippet: `<dependencyManagement>\n  <dependencies>\n    <dependency>\n      <groupId>${group}</groupId>\n      <artifactId>${artifact}</artifactId>\n      <version>${fixVersion}</version>\n    </dependency>\n  </dependencies>\n</dependencyManagement>`,
      },
      note: transitive
        ? "dependencyManagement forces this version wherever the artifact appears in the tree."
        : undefined,
    };
  }
  if (eco === "go" || eco.includes("golang")) {
    return { command: `go get ${pkg}@v${fixVersion.replace(/^v/, "")} && go mod tidy` };
  }
  if (eco === "crates.io" || eco.includes("cargo") || eco.includes("rust")) {
    return { command: `cargo update -p ${pkg} --precise ${fixVersion}` };
  }
  if (eco.includes("rubygems") || eco.includes("gem") || eco.includes("ruby")) {
    return { command: `bundle update ${pkg} --conservative` };
  }
  if (eco.includes("packagist") || eco.includes("composer") || eco.includes("php")) {
    return { command: `composer require ${pkg}:^${fixVersion}` };
  }
  if (eco.includes("nuget") || eco.includes(".net")) {
    return { command: `dotnet add package ${pkg} --version ${fixVersion}` };
  }
  return { note: `Upgrade ${pkg} to ${fixVersion} or later.` };
}

/** Advisory page for an OSV/GHSA/CVE id. */
export function advisoryUrl(id: string): string {
  if (/^GHSA-/i.test(id)) return `https://github.com/advisories/${id}`;
  if (/^CVE-/i.test(id)) return `https://nvd.nist.gov/vuln/detail/${id}`;
  return `https://osv.dev/vulnerability/${id}`;
}

/** MITRE page for a CWE id. */
export function cweUrl(cweId: string): string | null {
  const n = cweNumber(cweId);
  return n === null ? null : `https://cwe.mitre.org/data/definitions/${n}.html`;
}
