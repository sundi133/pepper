import { describe, it, expect } from "vitest";
import {
  SECRETS_AI_PROMPT,
  CONTAINER_CONFIG_PROMPT,
  K8S_MANIFEST_PROMPT,
} from "./prompts";
import { SYSTEM_PROMPT as SECRETS_CLASSIFIER_PROMPT } from "../secrets/llm-classifier";

/**
 * Coverage guards: each scanner prompt must explicitly name the high-signal
 * hardening classes drawn from the Cloud Security & Container Hardening skill.
 * Phrases are matched whitespace-tolerantly so re-wrapping prompt text does
 * not fail these assertions.
 */
describe("container config prompt detection coverage", () => {
  it("covers running as root and privileged execution", () => {
    expect(CONTAINER_CONFIG_PROMPT).toMatch(/root\s+user/i);
    expect(CONTAINER_CONFIG_PROMPT).toMatch(/privileged:\s*true/i);
  });

  it("covers unpinned base images and missing digest pins", () => {
    expect(CONTAINER_CONFIG_PROMPT).toMatch(/:latest/i);
    expect(CONTAINER_CONFIG_PROMPT).toMatch(/SHA256\s+digest/i);
  });

  it("covers build secrets baked into image layers", () => {
    expect(CONTAINER_CONFIG_PROMPT).toMatch(/docker\s+history/i);
    expect(CONTAINER_CONFIG_PROMPT).toMatch(/CWE-798/);
  });

  it("covers broad context copy and missing .dockerignore", () => {
    expect(CONTAINER_CONFIG_PROMPT).toMatch(/COPY\s+\.\s+\./);
    expect(CONTAINER_CONFIG_PROMPT).toMatch(/\.dockerignore/i);
  });

  it("covers host access and dangerous capabilities", () => {
    expect(CONTAINER_CONFIG_PROMPT).toMatch(/docker\.sock/i);
    expect(CONTAINER_CONFIG_PROMPT).toMatch(/SYS_ADMIN|NET_ADMIN/i);
  });

  it("covers missing resource limits and writable root FS", () => {
    expect(CONTAINER_CONFIG_PROMPT).toMatch(/no\s+resource\s+limits/i);
    expect(CONTAINER_CONFIG_PROMPT).toMatch(/read_only|writable\s+root/i);
  });

  it("covers multi-stage builds and setuid binaries", () => {
    expect(CONTAINER_CONFIG_PROMPT).toMatch(/multi-stage/i);
    expect(CONTAINER_CONFIG_PROMPT).toMatch(/setuid|setgid/i);
  });
});

describe("k8s manifest prompt detection coverage", () => {
  it("covers privileged execution and wildcard RBAC", () => {
    expect(K8S_MANIFEST_PROMPT).toMatch(/privileged:\s*true/i);
    expect(K8S_MANIFEST_PROMPT).toMatch(/wildcard\s*\(\*\)/i);
  });

  it("covers cluster-admin on service accounts", () => {
    expect(K8S_MANIFEST_PROMPT).toMatch(/cluster-admin/i);
    expect(K8S_MANIFEST_PROMPT).toMatch(/default\s+SA|service\s+account/i);
  });

  it("covers secrets in ConfigMaps and env vars", () => {
    expect(K8S_MANIFEST_PROMPT).toMatch(/ConfigMaps/i);
    expect(K8S_MANIFEST_PROMPT).toMatch(/secretKeyRef|env/i);
  });

  it("covers default-deny network policies", () => {
    expect(K8S_MANIFEST_PROMPT).toMatch(/default-deny/i);
    expect(K8S_MANIFEST_PROMPT).toMatch(/ingress|egress/i);
  });

  it("covers seccomp and apparmor profiles", () => {
    expect(K8S_MANIFEST_PROMPT).toMatch(/seccomp/i);
    expect(K8S_MANIFEST_PROMPT).toMatch(/AppArmor|RuntimeDefault/i);
  });

  it("covers pod security admission and image pinning", () => {
    expect(K8S_MANIFEST_PROMPT).toMatch(/Pod\s+Security\s+Admission|PSA/i);
    expect(K8S_MANIFEST_PROMPT).toMatch(/digest|mutable\s+tags/i);
  });

  it("covers hostPath volume abuse and dangerous service exposure", () => {
    expect(K8S_MANIFEST_PROMPT).toMatch(/hostPath/i);
    expect(K8S_MANIFEST_PROMPT).toMatch(/docker\.sock/i);
  });
});

describe("secrets AI prompt detection coverage", () => {
  it("requires context-based judgement of real vs fake credentials", () => {
    expect(SECRETS_AI_PROMPT).toMatch(/WHY\s+REAL/i);
    expect(SECRETS_AI_PROMPT).toMatch(/context/i);
  });

  it("names live provider credential formats", () => {
    expect(SECRETS_AI_PROMPT).toMatch(/AKIA|ghp_|sk-/i);
    expect(SECRETS_AI_PROMPT).toMatch(/JWT|session|webhook\s+signing/i);
  });

  it("names committed config/credential file types", () => {
    expect(SECRETS_AI_PROMPT).toMatch(/\.env|serviceAccountKey\.json|\.npmrc|\.pypirc|\.netrc/i);
    expect(SECRETS_AI_PROMPT).toMatch(/id_rsa|id_ed25519/i);
  });

  it("explicitly excludes env-var references and docs/examples", () => {
    expect(SECRETS_AI_PROMPT).toMatch(/environment\s+variable\s+name|process\.env/i);
    expect(SECRETS_AI_PROMPT).toMatch(/example|dummy|placeholder/i);
  });

  it("requires whyReal evidence for every finding", () => {
    expect(SECRETS_AI_PROMPT).toMatch(/whyReal/i);
    expect(SECRETS_AI_PROMPT).toMatch(/anti-false-positive/i);
  });
});

describe("secrets classifier prompt detection coverage", () => {
  it("judges from context, not just value shape", () => {
    expect(SECRETS_CLASSIFIER_PROMPT).toMatch(/full\s+context|file\s+path/i);
    expect(SECRETS_CLASSIFIER_PROMPT).toMatch(/not\s+just\s+the\s+value\s+shape/i);
  });

  it("keeps provider credential formats in the high-risk set", () => {
    expect(SECRETS_CLASSIFIER_PROMPT).toMatch(/AKIA|sk-ant|AIza/i);
    expect(SECRETS_CLASSIFIER_PROMPT).toMatch(/GITHUB_TOKEN|CI_JOB_TOKEN|Vault/i);
  });

  it("lists concrete false-positive contexts", () => {
    expect(SECRETS_CLASSIFIER_PROMPT).toMatch(/jest|mocha|seed/i);
    expect(SECRETS_CLASSIFIER_PROMPT).toMatch(/placeholders|hashes|checksums/i);
  });

  it("does not discount base64/encoded-looking real secrets", () => {
    expect(SECRETS_CLASSIFIER_PROMPT).toMatch(/base64/i);
  });
});