"use client";

import {
  Sheet,
  SheetContent,
  SheetDescription,
  SheetHeader,
  SheetTitle,
} from "@/components/ui/sheet";
import { SeverityBadge } from "./scan-status-badge";
import { Badge } from "@/components/ui/badge";
import { Separator } from "@/components/ui/separator";
import { ScrollArea } from "@/components/ui/scroll-area";
import { SCANNER_LABELS } from "@/lib/constants";
import {
  FileCode,
  Shield,
  Info,
  Copy,
  Target,
  Wrench,
  AlertTriangle,
  ExternalLink,
  Zap,
} from "lucide-react";
import { Button } from "@/components/ui/button";
import { toast } from "sonner";

interface Finding {
  id: string;
  scanner: string;
  severity: string;
  title: string;
  description: string;
  filePath?: string;
  startLine?: number;
  endLine?: number;
  snippet?: string;
  ruleId?: string;
  cweId?: string;
  cveId?: string;
  confidence?: number;
  metadata?: Record<string, unknown>;
}

interface FindingDetailPanelProps {
  finding: Finding | null;
  open: boolean;
  onClose: () => void;
}

// ─── Kill Chain Mapping ──────────────────────────────────────────────

interface KillChainStep {
  phase: string;
  description: string;
  active: boolean;
}

function getKillChain(finding: Finding): KillChainStep[] {
  const cwe = finding.cweId || "";
  const title = finding.title.toLowerCase();
  const desc = finding.description.toLowerCase();

  // Map finding to MITRE ATT&CK-inspired kill chain phases
  const phases: KillChainStep[] = [
    {
      phase: "Reconnaissance",
      description: "Attacker discovers the vulnerability",
      active: false,
    },
    {
      phase: "Weaponization",
      description: "Attacker crafts exploit payload",
      active: false,
    },
    {
      phase: "Delivery",
      description: "Exploit is delivered to target",
      active: false,
    },
    {
      phase: "Exploitation",
      description: "Vulnerability is triggered",
      active: false,
    },
    {
      phase: "Installation",
      description: "Persistent access established",
      active: false,
    },
    {
      phase: "Command & Control",
      description: "Attacker gains remote control",
      active: false,
    },
    {
      phase: "Impact",
      description: "Data exfiltration or damage",
      active: false,
    },
  ];

  // Injection vulnerabilities (SQLi, XSS, Command Injection)
  if (
    /injection|xss|command.*exec|rce|eval/i.test(title + desc) ||
    ["CWE-89", "CWE-79", "CWE-78", "CWE-94"].includes(cwe)
  ) {
    phases[0].active = true; // Recon: find input points
    phases[1].active = true; // Weaponize: craft payload
    phases[2].active = true; // Deliver: send malicious input
    phases[3].active = true; // Exploit: code executes
    if (/rce|command|exec|eval/i.test(title + desc)) {
      phases[4].active = true; // Install: backdoor
      phases[5].active = true; // C2: remote shell
    }
    phases[6].active = true; // Impact: data theft/damage
  }
  // Authentication / Access Control
  else if (
    /auth|access.control|bypass|idor|privilege|session/i.test(title + desc) ||
    ["CWE-287", "CWE-863", "CWE-639", "CWE-284"].includes(cwe)
  ) {
    phases[0].active = true;
    phases[2].active = true;
    phases[3].active = true;
    phases[6].active = true;
  }
  // Secrets / Credentials
  else if (
    /secret|credential|password|hardcoded|api.key|token/i.test(title + desc) ||
    ["CWE-798", "CWE-312", "CWE-522"].includes(cwe)
  ) {
    phases[0].active = true; // Recon: find exposed secret
    phases[3].active = true; // Exploit: use credential
    phases[5].active = true; // C2: access services
    phases[6].active = true; // Impact: data access
  }
  // SSRF
  else if (
    /ssrf|server.side.request/i.test(title + desc) ||
    cwe === "CWE-918"
  ) {
    phases[0].active = true;
    phases[1].active = true;
    phases[2].active = true;
    phases[3].active = true;
    phases[5].active = true;
    phases[6].active = true;
  }
  // Supply Chain / Dependency
  else if (
    /typosquat|malicious.*package|supply.chain|vulnerable.*depend/i.test(
      title + desc,
    ) ||
    ["CWE-506", "CWE-829"].includes(cwe)
  ) {
    phases[1].active = true;
    phases[2].active = true;
    phases[3].active = true;
    phases[4].active = true;
    phases[5].active = true;
    phases[6].active = true;
  }
  // IaC / Misconfiguration
  else if (
    /privileged|docker|container|terraform|kubernetes|iac/i.test(title + desc)
  ) {
    phases[0].active = true;
    phases[3].active = true;
    phases[4].active = true;
    phases[6].active = true;
  }
  // Default: at minimum recon, exploit, impact
  else {
    phases[0].active = true;
    phases[3].active = true;
    phases[6].active = true;
  }

  return phases;
}

// ─── Remediation Suggestions ─────────────────────────────────────────

interface Remediation {
  priority: "Immediate" | "Short-term" | "Long-term";
  action: string;
}

function getRemediations(finding: Finding): Remediation[] {
  const cwe = finding.cweId || "";
  const title = finding.title.toLowerCase();
  const desc = finding.description.toLowerCase();
  const remediations: Remediation[] = [];

  // Extract "Recommendation:" from description if present
  const recMatch = finding.description.match(
    /Recommendation:\s*(.+?)(?:\n|$)/i,
  );
  if (recMatch) {
    remediations.push({ priority: "Immediate", action: recMatch[1].trim() });
  }

  // SQL Injection
  if (/sql.*inject/i.test(title) || cwe === "CWE-89") {
    remediations.push(
      {
        priority: "Immediate",
        action:
          "Replace string concatenation with parameterized queries or prepared statements",
      },
      {
        priority: "Short-term",
        action:
          "Use an ORM (Prisma, SQLAlchemy, Hibernate) for all database operations",
      },
      {
        priority: "Long-term",
        action:
          "Implement input validation at API boundaries and add WAF rules for SQL injection patterns",
      },
    );
  }
  // XSS
  else if (/xss|cross.site.script/i.test(title) || cwe === "CWE-79") {
    remediations.push(
      {
        priority: "Immediate",
        action:
          "Encode all user-controlled output using context-appropriate encoding (HTML, JavaScript, URL)",
      },
      {
        priority: "Short-term",
        action:
          "Implement Content-Security-Policy headers to restrict inline script execution",
      },
      {
        priority: "Long-term",
        action:
          "Adopt a framework with auto-escaping (React, Vue) and add automated XSS testing to CI",
      },
    );
  }
  // Command Injection / RCE
  else if (
    /command.*inject|rce|remote.*code|eval/i.test(title) ||
    ["CWE-78", "CWE-94"].includes(cwe)
  ) {
    remediations.push(
      {
        priority: "Immediate",
        action:
          "Remove or replace the dangerous function (eval, exec, system) with safe alternatives",
      },
      {
        priority: "Short-term",
        action:
          "If shell execution is required, use allowlists for commands and arguments",
      },
      {
        priority: "Long-term",
        action:
          "Run the application in a sandboxed environment (container, seccomp, AppArmor)",
      },
    );
  }
  // Hardcoded Secrets
  else if (
    /secret|credential|hardcoded|password|api.key/i.test(title) ||
    ["CWE-798", "CWE-312"].includes(cwe)
  ) {
    remediations.push(
      {
        priority: "Immediate",
        action:
          "Rotate the exposed credential immediately and remove it from source code",
      },
      {
        priority: "Short-term",
        action:
          "Move secrets to environment variables or a secret manager (Vault, AWS Secrets Manager)",
      },
      {
        priority: "Long-term",
        action:
          "Add pre-commit hooks (e.g., gitleaks, truffleHog) to prevent future secret commits",
      },
    );
  }
  // SSRF
  else if (/ssrf/i.test(title) || cwe === "CWE-918") {
    remediations.push(
      {
        priority: "Immediate",
        action:
          "Validate and allowlist target URLs/hosts before making server-side requests",
      },
      {
        priority: "Short-term",
        action:
          "Block requests to internal IP ranges (10.x, 172.16.x, 169.254.x, localhost)",
      },
      {
        priority: "Long-term",
        action:
          "Use a dedicated HTTP proxy for outbound requests with network-level controls",
      },
    );
  }
  // Access Control / IDOR
  else if (
    /access.control|idor|authorization|privilege/i.test(title) ||
    ["CWE-863", "CWE-639"].includes(cwe)
  ) {
    remediations.push(
      {
        priority: "Immediate",
        action:
          "Add authorization checks to verify the requesting user owns or has access to the resource",
      },
      {
        priority: "Short-term",
        action:
          "Implement a centralized authorization middleware (RBAC/ABAC) applied to all routes",
      },
      {
        priority: "Long-term",
        action:
          "Add integration tests that verify access control for each endpoint and role combination",
      },
    );
  }
  // IaC / Container
  else if (
    /docker|container|terraform|kubernetes|iac|privileged/i.test(title)
  ) {
    remediations.push(
      {
        priority: "Immediate",
        action: "Fix the misconfiguration as described in the finding",
      },
      {
        priority: "Short-term",
        action:
          "Add IaC scanning (checkov, tfsec, trivy) to your CI/CD pipeline",
      },
      {
        priority: "Long-term",
        action:
          "Implement policy-as-code (OPA/Rego) to enforce security baselines",
      },
    );
  }
  // Supply Chain
  else if (
    /typosquat|malicious|supply.chain/i.test(title) ||
    cwe === "CWE-506"
  ) {
    remediations.push(
      {
        priority: "Immediate",
        action:
          "Verify the package is legitimate; remove if it's a typosquat or malicious",
      },
      {
        priority: "Short-term",
        action:
          "Enable lockfile integrity checks and use npm audit / pip-audit in CI",
      },
      {
        priority: "Long-term",
        action:
          "Use a private registry proxy (Artifactory, Nexus) with allowlisted packages",
      },
    );
  }
  // Vulnerable Dependency (SCA)
  else if (/vulnerable.*depend|cve-/i.test(title)) {
    const fixVersion = desc.match(/upgrade.*?to\s+(?:version\s+)?([\d.]+)/i);
    remediations.push(
      {
        priority: "Immediate",
        action: fixVersion
          ? `Upgrade to version ${fixVersion[1]} or later`
          : "Update to the latest patched version",
      },
      {
        priority: "Short-term",
        action:
          "Enable automated dependency update tools (Dependabot, Renovate)",
      },
      {
        priority: "Long-term",
        action:
          "Monitor dependencies with SCA scanning in CI and set up alerts for new CVEs",
      },
    );
  }

  // Deduplicate by action text
  const seen = new Set<string>();
  return remediations.filter((r) => {
    if (seen.has(r.action)) return false;
    seen.add(r.action);
    return true;
  });
}

// ─── CWE/CVE Link Helpers ────────────────────────────────────────────

function getCweUrl(cweId: string): string {
  const num = cweId.replace("CWE-", "");
  return `https://cwe.mitre.org/data/definitions/${num}.html`;
}

function getCveUrl(cveId: string): string {
  return `https://nvd.nist.gov/vuln/detail/${cveId}`;
}

// ─── Component ───────────────────────────────────────────────────────

export function FindingDetailPanel({
  finding,
  open,
  onClose,
}: FindingDetailPanelProps) {
  if (!finding) return null;

  const copyDescription = () => {
    navigator.clipboard.writeText(finding.description);
    toast.success("Copied to clipboard");
  };

  const killChain = getKillChain(finding);
  const remediations = getRemediations(finding);

  // Split description into main description and recommendation
  const descParts = finding.description.split(/\nRecommendation:\s*/i);
  const mainDescription = descParts[0];
  const embeddedRecommendation = descParts[1];

  const confidencePercent = finding.confidence
    ? finding.confidence <= 1
      ? Math.round(finding.confidence * 100)
      : Math.round(finding.confidence)
    : null;

  const confidenceColor =
    confidencePercent !== null
      ? confidencePercent >= 80
        ? "bg-green-500"
        : confidencePercent >= 60
          ? "bg-yellow-500"
          : "bg-red-500"
      : "bg-primary";

  return (
    <Sheet open={open} onOpenChange={(o) => !o && onClose()}>
      <SheetContent className="w-full sm:max-w-2xl p-0">
        {/* Header */}
        <div className="sticky top-0 z-10 bg-background border-b px-6 py-4">
          <SheetHeader className="space-y-3">
            <div className="flex items-center gap-2 flex-wrap">
              <SeverityBadge severity={finding.severity} />
              <Badge variant="outline" className="text-xs">
                {SCANNER_LABELS[
                  finding.scanner as keyof typeof SCANNER_LABELS
                ] || finding.scanner}
              </Badge>
              {confidencePercent !== null && (
                <Badge variant="secondary" className="text-xs font-mono">
                  {confidencePercent}% confidence
                </Badge>
              )}
            </div>
            <SheetTitle className="text-left text-lg leading-tight">
              {finding.title}
            </SheetTitle>
            <SheetDescription className="text-left flex items-center gap-3 flex-wrap">
              {finding.ruleId && (
                <code className="text-xs bg-muted px-1.5 py-0.5 rounded">
                  {finding.ruleId}
                </code>
              )}
              {finding.cweId && (
                <a
                  href={getCweUrl(finding.cweId)}
                  target="_blank"
                  rel="noopener noreferrer"
                  className="text-xs text-blue-600 hover:underline flex items-center gap-1"
                >
                  {finding.cweId}
                  <ExternalLink className="h-3 w-3" />
                </a>
              )}
              {finding.cveId && (
                <a
                  href={getCveUrl(finding.cveId)}
                  target="_blank"
                  rel="noopener noreferrer"
                  className="text-xs text-blue-600 hover:underline flex items-center gap-1"
                >
                  {finding.cveId}
                  <ExternalLink className="h-3 w-3" />
                </a>
              )}
            </SheetDescription>
          </SheetHeader>
        </div>

        <ScrollArea className="h-[calc(100vh-10rem)]">
          <div className="space-y-5 px-6 py-5">
            {/* Location */}
            {finding.filePath && (
              <section>
                <h4 className="text-sm font-semibold flex items-center gap-2 mb-2">
                  <FileCode className="h-4 w-4 text-muted-foreground" />
                  Location
                </h4>
                <div className="rounded-lg bg-muted/50 border p-3">
                  <p className="font-mono text-sm">
                    {finding.filePath}
                    {finding.startLine && (
                      <span className="text-muted-foreground">
                        :{finding.startLine}
                        {finding.endLine &&
                        finding.endLine !== finding.startLine
                          ? `-${finding.endLine}`
                          : ""}
                      </span>
                    )}
                  </p>
                </div>
              </section>
            )}

            {/* Code Snippet */}
            {finding.snippet && (
              <section>
                <h4 className="text-sm font-semibold flex items-center gap-2 mb-2">
                  <Shield className="h-4 w-4 text-muted-foreground" />
                  Vulnerable Code
                </h4>
                <pre className="rounded-lg bg-zinc-950 border border-zinc-800 p-4 text-sm text-zinc-100 overflow-x-auto font-mono leading-relaxed max-h-48">
                  {finding.snippet}
                </pre>
              </section>
            )}

            <Separator />

            {/* Description */}
            <section>
              <div className="flex items-center justify-between mb-2">
                <h4 className="text-sm font-semibold flex items-center gap-2">
                  <Info className="h-4 w-4 text-muted-foreground" />
                  Description
                </h4>
                <Button
                  variant="ghost"
                  size="sm"
                  className="h-7 text-xs"
                  onClick={copyDescription}
                >
                  <Copy className="h-3 w-3 mr-1" />
                  Copy
                </Button>
              </div>
              <div className="text-sm text-muted-foreground leading-relaxed whitespace-pre-wrap">
                {mainDescription}
              </div>
            </section>

            {/* Kill Chain */}
            <section>
              <h4 className="text-sm font-semibold flex items-center gap-2 mb-3">
                <Target className="h-4 w-4 text-muted-foreground" />
                Attack Kill Chain
              </h4>
              <div className="space-y-1">
                {killChain.map((step, i) => (
                  <div
                    key={step.phase}
                    className={`flex items-center gap-3 rounded-lg px-3 py-2 text-sm transition-colors ${
                      step.active
                        ? "bg-red-50 dark:bg-red-950/30 border border-red-200 dark:border-red-900"
                        : "bg-muted/30 text-muted-foreground"
                    }`}
                  >
                    <div
                      className={`flex h-6 w-6 shrink-0 items-center justify-center rounded-full text-xs font-bold ${
                        step.active
                          ? "bg-red-500 text-white"
                          : "bg-muted text-muted-foreground"
                      }`}
                    >
                      {i + 1}
                    </div>
                    <div className="flex-1 min-w-0">
                      <span
                        className={`font-medium ${
                          step.active ? "text-red-700 dark:text-red-400" : ""
                        }`}
                      >
                        {step.phase}
                      </span>
                      {step.active && (
                        <span className="text-xs text-muted-foreground ml-2">
                          {step.description}
                        </span>
                      )}
                    </div>
                    {step.active && (
                      <Zap className="h-3.5 w-3.5 text-red-500 shrink-0" />
                    )}
                  </div>
                ))}
              </div>
            </section>

            <Separator />

            {/* Suggested Remediation */}
            {remediations.length > 0 && (
              <section>
                <h4 className="text-sm font-semibold flex items-center gap-2 mb-3">
                  <Wrench className="h-4 w-4 text-muted-foreground" />
                  Suggested Remediation
                </h4>
                <div className="space-y-2">
                  {remediations.map((rem, i) => {
                    const priorityColor =
                      rem.priority === "Immediate"
                        ? "bg-red-100 text-red-700 dark:bg-red-950 dark:text-red-400 border-red-200 dark:border-red-900"
                        : rem.priority === "Short-term"
                          ? "bg-yellow-100 text-yellow-700 dark:bg-yellow-950 dark:text-yellow-400 border-yellow-200 dark:border-yellow-900"
                          : "bg-blue-100 text-blue-700 dark:bg-blue-950 dark:text-blue-400 border-blue-200 dark:border-blue-900";

                    return (
                      <div
                        key={i}
                        className="flex items-start gap-3 rounded-lg border p-3"
                      >
                        <Badge
                          variant="outline"
                          className={`text-[10px] shrink-0 mt-0.5 ${priorityColor}`}
                        >
                          {rem.priority}
                        </Badge>
                        <span className="text-sm leading-relaxed">
                          {rem.action}
                        </span>
                      </div>
                    );
                  })}
                </div>
              </section>
            )}

            {/* Embedded Recommendation (from LLM description) */}
            {embeddedRecommendation && remediations.length === 0 && (
              <section>
                <h4 className="text-sm font-semibold flex items-center gap-2 mb-2">
                  <Wrench className="h-4 w-4 text-muted-foreground" />
                  Recommendation
                </h4>
                <div className="rounded-lg border border-green-200 dark:border-green-900 bg-green-50 dark:bg-green-950/30 p-3 text-sm leading-relaxed">
                  {embeddedRecommendation}
                </div>
              </section>
            )}

            {/* Confidence Bar */}
            {confidencePercent !== null && (
              <section>
                <h4 className="text-sm font-semibold mb-2">Confidence</h4>
                <div className="flex items-center gap-3">
                  <div className="h-2.5 flex-1 rounded-full bg-muted overflow-hidden">
                    <div
                      className={`h-full rounded-full transition-all ${confidenceColor}`}
                      style={{ width: `${confidencePercent}%` }}
                    />
                  </div>
                  <span className="text-sm font-mono font-medium w-10 text-right">
                    {confidencePercent}%
                  </span>
                </div>
              </section>
            )}

            {/* Metadata */}
            {finding.metadata && Object.keys(finding.metadata).length > 0 && (
              <section>
                <h4 className="text-sm font-semibold flex items-center gap-2 mb-2">
                  <AlertTriangle className="h-4 w-4 text-muted-foreground" />
                  Additional Details
                </h4>
                <div className="rounded-lg bg-muted/50 border p-3 space-y-1.5">
                  {Object.entries(finding.metadata).map(([key, value]) => (
                    <div key={key} className="flex gap-2 text-sm">
                      <span className="font-medium text-muted-foreground min-w-[120px] shrink-0">
                        {key}:
                      </span>
                      <span className="font-mono break-all text-foreground">
                        {typeof value === "object"
                          ? JSON.stringify(value)
                          : String(value)}
                      </span>
                    </div>
                  ))}
                </div>
              </section>
            )}
          </div>
        </ScrollArea>
      </SheetContent>
    </Sheet>
  );
}
