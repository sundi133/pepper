import { readFileSync } from "node:fs";
import path from "node:path";
import { load } from "js-yaml";
import { describe, expect, it } from "vitest";
import { buildCiTemplates, groovySingleQuoted, indentBlock } from "./cicd-templates";

const SH = readFileSync(path.join(process.cwd(), "public/ci/pepper-scan.sh"), "utf8").trimEnd();
const PS1 = readFileSync(path.join(process.cwd(), "public/ci/pepper-scan.ps1"), "utf8").trimEnd();
const t = buildCiTemplates();

type Step = { run?: string; name?: string; displayName?: string; inputs?: { script?: string }; env?: Record<string, string> };

describe("CI templates", () => {
  it("offers GitHub, GitLab, Jenkins and Azure DevOps (Linux + Windows agents)", () => {
    expect(Object.keys(t).sort()).toEqual(
      ["azure-devops", "azure-devops-windows", "azure-pipelines", "github", "github-actions", "gitlab", "jenkins"].sort(),
    );
  });

  it("GitHub Actions: valid YAML embedding the scan script verbatim", () => {
    const doc = load(t.github.body) as { jobs: { scan: { steps: Step[] } } };
    const step = doc.jobs.scan.steps.find((s) => s.name === "Pepper scan")!;
    expect(step.run!.trimEnd()).toBe(SH);
    expect(step.env).toMatchObject({ PEPPER_ERROR_PREFIX: "::error::" });
  });

  it("GitLab CI: valid YAML embedding the scan script verbatim", () => {
    const doc = load(t.gitlab.body) as { pepper_security: { script: string[] } };
    expect(doc.pepper_security.script[0].trimEnd()).toBe(SH);
  });

  it("Azure Pipelines (Linux): script verbatim, secret mapped explicitly, ADO error annotations", () => {
    const doc = load(t["azure-devops"].body) as { steps: Step[]; variables: Array<{ group: string }> };
    expect(doc.variables).toEqual([{ group: "pepper" }]);
    const scan = doc.steps.find((s) => s.displayName === "Pepper security scan")!;
    expect(scan.inputs!.script!.trimEnd()).toBe(SH);
    expect(scan.env).toMatchObject({
      PEPPER_API_KEY: "$(PEPPER_API_KEY)",
      PEPPER_PROJECT: "$(Build.Repository.Name)",
      PEPPER_ERROR_PREFIX: "##vso[task.logissue type=error]",
    });
  });

  it("Azure Pipelines (Windows): PowerShell script verbatim", () => {
    const doc = load(t["azure-devops-windows"].body) as { steps: Step[] };
    const scan = doc.steps.find((s) => s.displayName === "Pepper security scan")!;
    expect(scan.inputs!.script!.trimEnd()).toBe(PS1);
  });

  it("Jenkins: the ''' string decodes back to the exact script", () => {
    const m = t.jenkins.body.match(/sh '''\n([\s\S]*?)\n\s*'''/);
    expect(m).not.toBeNull();
    const decoded = m![1]
      .split("\n")
      .map((l) => l.replace(/^ {12}/, ""))
      .join("\n")
      .replace(/\\\\/g, "\\");
    expect(decoded).toBe(SH);
  });

  it("uses the API's real upload fields (the old templates sent `source=`, which the API ignores)", () => {
    for (const key of ["github", "gitlab", "jenkins", "azure-devops"]) {
      expect(t[key].body).toContain("file=@");
      expect(t[key].body).not.toContain("source=@");
    }
    expect(SH).toContain("type=application/gzip");
    expect(SH).toContain("projectName");
  });
});

describe("helpers", () => {
  it("indentBlock leaves blank lines empty", () => {
    expect(indentBlock("a\n\nb", 2)).toBe("  a\n\n  b");
  });
  it("groovySingleQuoted doubles backslashes and refuses '''", () => {
    expect(groovySingleQuoted("printf '%s\\n'")).toBe("printf '%s\\\\n'");
    expect(() => groovySingleQuoted("x'''y")).toThrow();
  });
});
