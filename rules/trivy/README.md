# Rule-based IaC scanning (trivy config)

Pepper runs `trivy config` (Trivy: Apache-2.0; checks: MIT) on FULL, IAC_ONLY
and K8S_ONLY scans, whether or not LLM analysis is enabled.

- **Covers:** Terraform, CloudFormation, Azure ARM, Kubernetes manifests (found
  by content anywhere in the repo), Helm charts (rendered with their
  `values.yaml`) and Ansible. Kubernetes/Helm findings appear under
  **Kubernetes**; the rest under **IaC Security**. Dockerfiles are handled by
  the existing Dockerfile checks in the container scanner.
- **Offline and private:** uses the checks embedded in the Trivy binary
  (`--skip-check-update`), with `--disable-telemetry` and
  `--skip-version-check`, so nothing leaves the network. No extra service — the
  `trivy` binary already ships in the worker image.
- **Precision:** `iac-policy.json` sets the minimum severity (HIGH), disables
  checks that are best-practice noise (each with the reason), and groups related
  checks (e.g. the four S3 public-access settings) into one finding per
  resource. Override with `IAC_MIN_SEVERITY` / `IAC_EXCLUDE_CHECKS`, or point
  `IAC_POLICY_FILE` at your own policy.

Tuned on TerraGoat, Kubernetes Goat, terraform-aws-vpc, terraform-aws-eks and
grafana/helm-charts (see the PR description for the numbers).
