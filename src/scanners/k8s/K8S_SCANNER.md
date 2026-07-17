# Kubernetes (K8S) Scanner

## Overview

The K8S scanner analyzes Kubernetes manifest files (YAML) for security misconfigurations and vulnerabilities. It uses LLM-powered analysis to identify security risks without hardcoding any rules.

## Features

- **File Discovery**: Automatically finds manifest files in `k8s/`, `kubernetes/`, `helm/`, and `manifests/` directories
- **LLM-Powered Analysis**: Uses Claude to intelligently analyze manifests for security issues
- **Structured Findings**: Returns findings in a consistent, actionable format
- **Batch Processing**: Processes manifests in batches to stay within token limits
- **Metadata Extraction**: Automatically extracts Kubernetes metadata (kind, name, namespace) from manifests

## Supported Checks

The scanner identifies security issues in:

1. **Privileged Containers** - `securityContext.privileged: true`
2. **RBAC Overprivilege** - Wildcard (*) permissions in rules
3. **Missing Resource Limits** - Containers without CPU/memory limits
4. **Insecure Image Policies** - `imagePullPolicy: Always` with `:latest` tags
5. **Secrets in ConfigMaps** - Plaintext secrets instead of Secret objects
6. **Host Access** - `hostNetwork`, `hostPID`, `hostIPC` enabled
7. **Missing Security Context** - No `runAsNonRoot`, capability restrictions
8. **Missing Network Policies** - No ingress/egress restrictions
9. **Running as Root** - `runAsUser: 0` or root default
10. **Missing Health Probes** - No `livenessProbe` or `readinessProbe`
11. **Service Account Token Auto-mount** - `automountServiceAccountToken: true`
12. **Dangerous Linux Capabilities** - SYS_ADMIN, NET_ADMIN, etc.

## Output Format

Each finding follows this structure (driven by AI, not hardcoded):

```json
{
  "scanner": "K8S",
  "severity": "CRITICAL|HIGH|MEDIUM|LOW",
  "title": "Human-readable issue title",
  "description": "Detailed explanation of the issue",
  "filePath": "k8s/deployments/postgres.yaml",
  "startLine": 10,
  "endLine": 10,
  "snippet": "securityContext:\n  privileged: true",
  "cweId": "CWE-250",
  "confidence": 0.95,
  "ruleId": "K8S-PrivilegedExecution",
  "metadata": {
    "whatIsWrong": "Pod runs with privileged mode enabled",
    "where": "k8s/deployments/postgres.yaml:10",
    "whyExploitable": "Container escape allows full host compromise",
    "fix": "Remove 'privileged: true' from securityContext",
    "resourceType": "Deployment",
    "namespace": "production",
    "resourceName": "postgres",
    "issueCategory": "PrivilegedExecution"
  }
}
```

## Severity Levels

- **CRITICAL**: Immediate compromise risk (privileged containers, wildcard RBAC)
- **HIGH**: Significant risk with plausible exploit (missing limits, unencrypted secrets)
- **MEDIUM**: Defense-in-depth gap (missing probes, no capability dropping)
- **LOW**: Configuration hardening opportunity

## Configuration

Environment variables:

```bash
K8S_MIN_CONFIDENCE=0.80  # Minimum confidence threshold (default: 0.80)
```

## How It Works

1. **Discovery Phase**
   - Scans file list for `.yaml` and `.yml` files in K8s directories
   - Extracts Kubernetes metadata (kind, name, namespace) from each manifest

2. **Batch Processing**
   - Processes manifests in batches of 10 to stay within token limits
   - Groups manifests with context for LLM analysis

3. **LLM Analysis**
   - Sends manifest content + predefined security checklist to Claude
   - LLM identifies issues without any hardcoded patterns
   - Returns structured JSON with findings

4. **Enrichment**
   - Validates confidence scores (>= 0.80)
   - Applies severity calibration
   - Enriches with structured metadata (what's wrong, why, how to fix)
   - Extracts file-specific context

5. **Output**
   - Returns deduped findings in standard RawFinding format
   - Each finding includes actionable remediation advice

## Integration

The K8S scanner is fully integrated into the scanner pipeline:

- Activated with scan types: `FULL`, `K8S_ONLY`
- Requires `enableLlmSast: true` in org settings
- Runs in parallel with other scanners
- Deduplicates findings across all scanners

## Examples

### Example 1: Privileged Container

**Input**: `k8s/deployments/postgres.yaml`
```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: postgres
  namespace: production
spec:
  containers:
  - name: db
    image: postgres:15
    securityContext:
      privileged: true  # Line 10
```

**Output**:
```json
{
  "scanner": "K8S",
  "severity": "CRITICAL",
  "title": "Pod runs with privileged=true",
  "description": "The pod is running with privileged mode enabled. A privileged container has almost unrestricted access to the host and all Linux capabilities.",
  "filePath": "k8s/deployments/postgres.yaml",
  "startLine": 10,
  "metadata": {
    "whatIsWrong": "Privileged container execution enabled",
    "whyExploitable": "Container escape allows full host compromise",
    "fix": "Remove 'privileged: true' and use specific capabilities only",
    "resourceType": "Deployment",
    "namespace": "production"
  }
}
```

### Example 2: Overprivileged RBAC

**Input**: `k8s/rbac/admin-role.yaml`
```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: admin
rules:
- apiGroups: ["*"]
  resources: ["*"]
  verbs: ["*"]
```

**Output**:
```json
{
  "scanner": "K8S",
  "severity": "CRITICAL",
  "title": "ClusterRole grants wildcard permissions",
  "description": "The Role grants wildcard (*) permissions on all resources and actions. This violates least privilege principles.",
  "filePath": "k8s/rbac/admin-role.yaml",
  "metadata": {
    "whatIsWrong": "Overprivileged RBAC configuration",
    "whyExploitable": "Complete Kubernetes cluster compromise possible",
    "fix": "Grant only required permissions per resource and action",
    "resourceType": "ClusterRole"
  }
}
```

## No Hardcoding

**Important**: This scanner does NOT hardcode any security rules or issue detection logic. Instead:

- The LLM prompt (`K8S_MANIFEST_PROMPT` in `prompts.ts`) provides security knowledge
- Claude analyzes each manifest dynamically
- Issues are identified based on actual manifest content
- Findings are AI-generated, not pattern-matched
- You can modify the prompt to check for new issue types without code changes

## Files Modified/Created

- `src/scanners/k8s/index.ts` - K8S scanner implementation
- `src/scanners/shared/prompts.ts` - K8S_MANIFEST_PROMPT added
- `src/scanners/types.ts` - "K8S" added to ScannerType
- `src/scanners/index.ts` - K8S scanner integrated
- `src/lib/constants.ts` - K8S_MIN_CONFIDENCE_DEFAULT added

## Testing

To test the K8S scanner:

```bash
# Run full scans (includes K8S)
npm run test

# Or test directly with K8S_ONLY scan type
# (in your scan configuration)
```

## Troubleshooting

### No findings returned
- Ensure manifest files are in `k8s/`, `kubernetes/`, `helm/`, or `manifests/` directories
- Check that `enableLlmSast: true` in org settings
- Verify `K8S_MIN_CONFIDENCE >= 0.80` (or adjust the threshold)

### Low confidence scores
- The LLM may be uncertain about the finding
- Lower the confidence threshold in K8S_MIN_CONFIDENCE env var
- Or provide more context in the manifest file

### Token limit exceeded
- Scanner batches manifests in groups of 10
- If a single manifest > 15KB, it's truncated
- Consider splitting large manifests

## Future Enhancements

- Support for Helm template analysis
- Custom security policies via prompt customization
- Integration with Kyverno for policy validation
- Multi-document YAML file support
