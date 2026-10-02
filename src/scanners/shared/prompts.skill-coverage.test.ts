import { describe, it, expect } from "vitest";
import {
  SECRETS_AI_PROMPT,
  CONTAINER_CONFIG_PROMPT,
  K8S_MANIFEST_PROMPT,
  MALICIOUS_VALIDATION_PROMPT,
} from "./prompts";
import { SYSTEM_PROMPT as SECRETS_CLASSIFIER_PROMPT } from "../secrets/llm-classifier";
import { ZERO_DAY_SYSTEM_PROMPT } from "../zero-day/prompts";
import { IAC_STACK_PROMPT } from "../iac";

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

  it("names committed credential files and modern provider formats", () => {
    expect(SECRETS_CLASSIFIER_PROMPT).toMatch(/\.git-credentials|kubeconfig|terraform\.tfstate/i);
    expect(SECRETS_CLASSIFIER_PROMPT).toMatch(/github_pat_|Azure Storage|SAS token/i);
  });
});

/**
 * Guards drawn from the detecting-malicious-npm-packages / supply-chain
 * simulation skills: install-script malware has concrete behavioural markers
 * that must be named so the validator emits them rather than dismissing a
 * script as a "normal build step".
 */
describe("malicious-package validation prompt detection coverage", () => {
  it("covers credential/secret exfiltration from install scripts", () => {
    expect(MALICIOUS_VALIDATION_PROMPT).toMatch(/exfiltrat/i);
    expect(MALICIOUS_VALIDATION_PROMPT).toMatch(/\.npmrc|process\.env/i);
  });

  it("covers remote code execution and obfuscation markers", () => {
    expect(MALICIOUS_VALIDATION_PROMPT).toMatch(/curl\/wget\s+piped\s+to/i);
    expect(MALICIOUS_VALIDATION_PROMPT).toMatch(/base64|eval|Buffer\.from/i);
  });

  it("covers reverse shells, cryptomining and worming", () => {
    expect(MALICIOUS_VALIDATION_PROMPT).toMatch(/reverse shell|nc\/socat/i);
    expect(MALICIOUS_VALIDATION_PROMPT).toMatch(/xmrig|mining pool|stratum/i);
    expect(MALICIOUS_VALIDATION_PROMPT).toMatch(/worming|self-propagat/i);
  });

  it("covers dependency confusion", () => {
    expect(MALICIOUS_VALIDATION_PROMPT).toMatch(/dependency confusion/i);
  });
});

/**
 * Guards drawn from the container-hardening / container-escape skills: beyond
 * the classic privileged/root checks, these are the concrete build-time
 * primitives that let a container image become an attack vector.
 */
describe("container prompt additional hardening coverage", () => {
  it("covers remote ADD and curl-pipe RUN execution", () => {
    expect(CONTAINER_CONFIG_PROMPT).toMatch(/Remote\s+ADD|curl-pipe\s+RUN/i);
    expect(CONTAINER_CONFIG_PROMPT).toMatch(/checksum\/signature|chmod\s+\+x/i);
  });

  it("covers no-new-privileges and untrusted base images", () => {
    expect(CONTAINER_CONFIG_PROMPT).toMatch(/no-new-privileges/i);
    expect(CONTAINER_CONFIG_PROMPT).toMatch(/Untrusted\s+base\s+image|verified\s+publisher/i);
  });

  it("covers credentials copied in and ONBUILD triggers", () => {
    expect(CONTAINER_CONFIG_PROMPT).toMatch(/\.git-credentials|id_rsa/i);
    expect(CONTAINER_CONFIG_PROMPT).toMatch(/ONBUILD/i);
  });
});

/**
 * Guards drawn from the pod-security / network-policy skills: exposure and
 * schema-level misconfigurations that the pod-template-only checks miss.
 */
describe("k8s prompt additional hardening coverage", () => {
  it("covers port and service exposure", () => {
    expect(K8S_MANIFEST_PROMPT).toMatch(/hostPort|NodePort/i);
    expect(K8S_MANIFEST_PROMPT).toMatch(/externalIPs/i);
  });

  it("covers unsafe sysctls and deprecated API versions", () => {
    expect(K8S_MANIFEST_PROMPT).toMatch(/sysctls/i);
    expect(K8S_MANIFEST_PROMPT).toMatch(/extensions\/v1beta1|policy\/v1beta1/i);
  });

  it("covers init/ephemeral container security gaps and default namespace", () => {
    expect(K8S_MANIFEST_PROMPT).toMatch(/initContainers|ephemeralContainers/i);
    expect(K8S_MANIFEST_PROMPT).toMatch(/default\s+namespace|default\s+service\s+account/i);
  });
});

/**
 * Guards drawn from the Terraform/cloud-CIS skills: provider-specific
 * misconfigurations that must be named to be detected.
 */
describe("IaC prompt cloud hardening coverage", () => {
  it("covers IMDSv1 and S3 block-public-access gaps", () => {
    expect(IAC_STACK_PROMPT).toMatch(/IMDSv1|http_tokens/i);
    expect(IAC_STACK_PROMPT).toMatch(/Block\s+Public\s+Access/i);
  });

  it("covers CloudTrail and public database exposure", () => {
    expect(IAC_STACK_PROMPT).toMatch(/CloudTrail/i);
    expect(IAC_STACK_PROMPT).toMatch(/publicly_accessible/i);
  });

  it("covers EKS/GKE/Azure control-plane and NSG exposure", () => {
    expect(IAC_STACK_PROMPT).toMatch(/enable_legacy_abac|public_access_cidrs/i);
    expect(IAC_STACK_PROMPT).toMatch(/NSG\s+rule|any\/any/i);
  });
});

/**
 * Guards drawn from the web-app/access-control testing skills: authentication
 * lifecycle flaws that per-file SAST and pattern rules commonly miss.
 */
describe("zero-day prompt auth-lifecycle coverage", () => {
  it("covers account enumeration and forced browsing", () => {
    expect(ZERO_DAY_SYSTEM_PROMPT).toMatch(/enumeration/i);
    expect(ZERO_DAY_SYSTEM_PROMPT).toMatch(/Forced browsing|function-level authorization/i);
  });

  it("covers rounding and gift-card/refund abuse", () => {
    expect(ZERO_DAY_SYSTEM_PROMPT).toMatch(/rounding arbitrage/i);
    expect(ZERO_DAY_SYSTEM_PROMPT).toMatch(/Gift card|refund abuse/i);
  });
});