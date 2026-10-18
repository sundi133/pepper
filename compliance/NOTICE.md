# Compliance catalog sources and licenses

| File | Source | License |
|---|---|---|
| `OWASP_ASVS.json` | OWASP Application Security Verification Standard 4.0.3, [OWASP/ASVS](https://github.com/OWASP/ASVS) tag `v4.0.3`: 278 active requirements, levels and official CWE mappings. Requirement text unchanged except markdown links removed; `[DELETED]` placeholders omitted. | [CC BY-SA 4.0](https://creativecommons.org/licenses/by-sa/4.0/) © OWASP Foundation. This file is shared under the same license. |
| `CIS_Kubernetes_Benchmark.json`, `CIS_EKS_Benchmark.json`, `CIS_AWS_Foundations_Benchmark.json` | Control ids, titles and check mappings from [aquasecurity/trivy-checks](https://github.com/aquasecurity/trivy-checks) `pkg/compliance/*.yaml` (commit recorded in each file's `source`) | MIT (Aqua Security). CIS® and CIS Benchmarks® are trademarks of the Center for Internet Security. The full benchmarks are published at [cisecurity.org](https://www.cisecurity.org/cis-benchmarks). |
| `DISA_ASD_STIG.json` | DISA Application Security and Development STIG, Version 6 Release 5 (benchmark date 30 Sep 2026), [`U_ASD_V6R5_STIG.zip`](https://dl.dod.cyber.mil/wp-content/uploads/stigs/zip/U_ASD_V6R5_STIG.zip) (SHA-256 `b73e8a74d591982d49cdc9e0c5c0023b37ab87d91f3f3f150d6dab8baa23c435`), file `U_ASD_STIG_V6R5_Manual-xccdf.xml`: all 286 requirements with Vuln ID, Rule ID, STIG ID, CAT, SRG, CCIs and discussion text, unchanged except whitespace. NIST SP 800-53 Rev 5 references from the DISA [CCI List](https://dl.dod.cyber.mil/wp-content/uploads/stigs/zip/U_CCI_List.zip) (2025-01-23). The CWE crosswalk is Pepper's own (`scripts/compliance/asd-stig-mapping.mjs`). | U.S. Government work, published by DISA on [public.cyber.mil](https://public.cyber.mil/stigs/). |
| `CIS_Docker_Benchmark.json` | Pepper-authored summaries of selected CIS Docker Benchmark 1.6 controls. The rule-id mapping is Pepper's own. | Pepper |
| Other `*.json` | Pepper-authored catalogs and crosswalks | Pepper |

Regenerate the ASVS, CIS and ASD STIG catalogs with:

```bash
scripts/compliance/fetch-sources.sh /tmp/compliance-src
node scripts/compliance/build-frameworks.mjs /tmp/compliance-src "$(cat /tmp/compliance-src/trivy-checks.sha)"
```

For a new ASD STIG release, bump `ASD_STIG` in `fetch-sources.sh` and review
`asd-stig-mapping.mjs`: the build stops if a mapped Vuln ID is gone or now
carries a different STIG ID.

**Not bundled:** CIS Controls v8 and the full CIS Benchmark documents
(CC BY-NC-ND / CC BY-NC-SA, which don't permit redistribution in a commercial
product). Organizations with CIS SecureSuite access can add their own
catalogs: drop a JSON file in this folder with the same shape (`name`,
`version`, `controls[]` with `controlId`, `title`, `summary`, and optionally
`cweMapping` / `ruleMapping`), or a text-based PDF for LLM mapping.
