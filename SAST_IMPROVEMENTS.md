# SAST Scanner Improvements - Multi-Language Support

## Current Status

Your SAST scanner **SUPPORTS** TypeScript/JavaScript files:
- ✅ `.ts` (TypeScript)
- ✅ `.tsx` (React/JSX TypeScript)
- ✅ `.js` (JavaScript)
- ✅ `.jsx` (React/JSX)
- ✅ `.py` (Python)
- ✅ 20+ other languages

## Why TypeScript Files Weren't Scanned

The issue is likely one of these:

### 1. **File List Generation Issue** ⚠️
The `ctx.fileList` passed to the scanner may not include TypeScript files.

**Location:** `src/worker/scanner.ts` or wherever `ScanContext.fileList` is built

**Fix:**
```typescript
// In scan context builder, ensure ALL languages are included
const filesToScan = files.filter(f => {
  const ext = path.extname(f).toLowerCase();
  return FILE_EXTENSIONS[ext]; // This checks all supported types
});
```

### 2. **Repository Git Ignore Issue** ⚠️
If scanning via `git ls-files`, make sure TypeScript files aren't excluded:

```bash
# Check what files git is tracking
git ls-files | grep -E '\.(ts|tsx|js|jsx)$'

# If empty, check .gitignore
cat .gitignore | grep -E '(ts|js|tsx|jsx)'
```

### 3. **File Walk/Discovery Issue** ⚠️
If files are discovered via `fs.walk`, ensure extension matching is case-insensitive:

```typescript
// ✅ GOOD - case insensitive
const ext = path.extname(filePath).toLowerCase();

// ❌ WRONG - case sensitive (will miss .TS, .Ts)
const ext = path.extname(filePath);
```

## How to Verify & Fix

### Step 1: Check What Files Are Being Scanned

Add logging to see all files discovered:

```typescript
// In src/scanners/sast/llm-analyzer.ts, around line 274
logger.info(
  {
    totalFiles: ctx.fileList.length,
    byExtension: ctx.fileList.reduce((acc, f) => {
      const ext = path.extname(f).toLowerCase();
      acc[ext] = (acc[ext] || 0) + 1;
      return acc;
    }, {} as Record<string, number>),
    pythonFiles: ctx.fileList.filter(f => f.endsWith('.py')).length,
    typescriptFiles: ctx.fileList.filter(f => /\.(ts|tsx)$/.test(f)).length,
  },
  "File discovery stats"
);
```

### Step 2: Check File Extension Support

**Current support (in `src/lib/constants.ts`):**
```typescript
export const FILE_EXTENSIONS: Record<string, string> = {
  ".js": "javascript",
  ".jsx": "javascript",
  ".ts": "typescript",
  ".tsx": "typescript",
  ".py": "python",
  ".go": "go",
  ".java": "java",
  ".rb": "ruby",
  ".php": "php",
  ".cs": "csharp",
  ".rs": "rust",
  // ... 12 more languages
};
```

### Step 3: Enable Language-Specific Rules

Create TypeScript-specific security rules in your LLM prompts:

```typescript
// Add to src/scanners/sast/llm-analyzer.ts
const TYPESCRIPT_SPECIFIC_RULES = `
For TypeScript/JavaScript files, prioritize:
1. **NoSQL Injection** — Dynamic MongoDB queries without schema validation
   Example: db.collection.find({ _id: userInput })
2. **XSS in Templates** — Unescaped HTML in JSX or template literals
   Example: <div dangerouslySetInnerHTML={{__html: userInput}} />
3. **Path Traversal** — Path operations without normalization
   Example: fs.readFile(path.join('/uploads', userPath))
4. **Crypto Misuse** — Weak algorithms, missing IV/salt
   Example: crypto.createCipher('aes-256-cbc', key) // Deprecated
5. **Prototype Pollution** — Object.assign with untrusted input
   Example: Object.assign(obj, userInput)
6. **Insecure Deserialization** — eval(), Function() with user input
   Example: Function(userCode)()
7. **SSRF in fetch** — fetch() with user-controlled URLs
   Example: fetch(userUrl)
8. **Command Injection** — Child process without escaping
   Example: exec(\`command \${userInput}\`)
`;
```

### Step 4: Enhance Language Detection

Update the LLM prompt to handle multi-language repositories:

```typescript
const MULTI_LANGUAGE_CONTEXT = `
This repository contains multiple programming languages.
Each file MUST be analyzed using language-specific security rules:

- **Python files (.py):** SQL injection, pickle deserialization, path traversal, LDAP injection
- **TypeScript/JavaScript (.ts, .tsx, .js, .jsx):** XSS, NoSQL injection, prototype pollution, eval() abuse
- **Go files (.go):** Race conditions, defer panic, goroutine leaks, unsafe memory
- **Java files (.java):** Deserialization gadgets, XXE, SQL injection, weak cryptography
- **Docker/Container:** Privileged containers, hardcoded secrets, outdated images
- **IaC (Terraform/Helm):** Overpermissive IAM, exposed secrets, misconfigured networking

Analyze EACH file according to its language context.
`;
```

## Improvements to Implement

### 1. Multi-Language SAST Pass

**File:** `src/scanners/sast/llm-analyzer.ts`

```typescript
// After line 273, add language-aware context
const languageStats = ctx.fileList.reduce((acc, f) => {
  const ext = path.extname(f).toLowerCase();
  const lang = FILE_EXTENSIONS[ext];
  if (lang) acc[lang] = (acc[lang] || 0) + 1;
  return acc;
}, {} as Record<string, number>);

const languageContext = buildLanguageContext(languageStats);
const enhancedPrompt = finalPrompt + languageContext;
```

### 2. Per-Language Security Checks

Create separate analyzers for each language:

```typescript
// src/scanners/sast/analyzers/typescript-analyzer.ts
export const typescriptSecurityRules = {
  "XSS_DANGEROUSLYSETINNERHTML": {
    pattern: /dangerouslySetInnerHTML\s*=\s*{{\s*__html/,
    severity: "HIGH",
    rule: "Unescaped HTML in JSX can lead to XSS"
  },
  "NOSQL_INJECTION": {
    pattern: /db\.(collection|find|aggregate)\s*\(\s*[^"'`{]/,
    severity: "CRITICAL",
    rule: "Dynamic NoSQL query without validation"
  },
  "EVAL_USAGE": {
    pattern: /\beval\s*\(|Function\s*\(/,
    severity: "CRITICAL",
    rule: "eval() or Function() can execute arbitrary code"
  }
};
```

### 3. Enhanced File Discovery

```typescript
// src/lib/file-scanner.ts
export function discoverScannable Files(root: string): string[] {
  const files: string[] = [];
  
  function walk(dir: string) {
    for (const entry of fs.readdirSync(dir)) {
      const full = path.join(dir, entry);
      const rel = path.relative(root, full);
      
      // Skip binary/vendor directories
      if (SKIP_DIRECTORIES.has(entry)) continue;
      
      const stat = fs.statSync(full);
      if (stat.isDirectory()) {
        walk(full);
      } else {
        const ext = path.extname(entry).toLowerCase();
        // Include ALL supported extensions
        if (FILE_EXTENSIONS[ext] && !BINARY_EXTENSIONS.has(ext)) {
          files.push(rel);
        }
      }
    }
  }
  
  walk(root);
  return files;
}
```

### 4. Language-Aware Chunking

```typescript
// src/scanners/sast/llm-analyzer.ts - enhance chunking for language
function getChunkContext(filePath: string, lang: string): string {
  const contexts: Record<string, string> = {
    typescript: "Analyze as TypeScript - check for XSS, SSRF, NoSQL injection, prototype pollution",
    python: "Analyze as Python - check for SQL injection, pickle abuse, path traversal",
    go: "Analyze as Go - check for race conditions, goroutine leaks, buffer overflows",
    java: "Analyze as Java - check for deserialization gadgets, XXE, weak crypto",
  };
  
  return contexts[lang] || "Perform general security analysis";
}
```

## Complete File Discovery Algorithm

```typescript
export async function collectAllFilesForScan(
  root: string,
  filterByLanguages?: string[]
): Promise<string[]> {
  const files: string[] = [];
  const targetLangs = filterByLanguages
    ? new Set(filterByLanguages)
    : null;

  async function walk(dir: string): Promise<void> {
    try {
      const entries = await fs.promises.readdir(dir);
      
      for (const entry of entries) {
        const fullPath = path.join(dir, entry);
        const relPath = path.relative(root, fullPath);
        const ext = path.extname(entry).toLowerCase();
        
        // Skip directories
        if (SKIP_DIRECTORIES.has(entry)) continue;
        
        const stat = await fs.promises.stat(fullPath);
        
        if (stat.isDirectory()) {
          await walk(fullPath);
        } else if (stat.isFile()) {
          // Check if supported
          const language = FILE_EXTENSIONS[ext];
          if (!language) continue;
          
          // Filter by language if specified
          if (targetLangs && !targetLangs.has(language)) continue;
          
          // Skip binaries
          if (BINARY_EXTENSIONS.has(ext)) continue;
          
          files.push(relPath);
        }
      }
    } catch (err) {
      logger.warn({ dir, err }, "Error reading directory");
    }
  }
  
  await walk(root);
  return files;
}
```

## Testing Your Fix

### 1. Create Test Repository Structure

```bash
mkdir -p test-repo/{src,lib,api,services}
cat > test-repo/vulnerable.ts << 'EOF'
import * as fs from 'fs';

// XSS vulnerability
function renderUserInput(input: string) {
  return <div dangerouslySetInnerHTML={{__html: input}} />;
}

// SQL-like injection (NoSQL)
function findUser(id: string) {
  return db.users.findOne({ _id: id }); // No validation
}

// Path traversal
function readFile(filename: string) {
  return fs.readFileSync(filename, 'utf-8');
}
EOF

cat > test-repo/vulnerable.py << 'EOF'
import sqlite3

# SQL injection
def get_user(user_id):
    query = f"SELECT * FROM users WHERE id = {user_id}"
    return db.execute(query)

# Pickle deserialization
import pickle
user_data = pickle.loads(user_input)
EOF
```

### 2. Scan the Test Repository

```bash
# Manually run SAST on the test repo
curl -X POST http://localhost:3000/api/scans \
  -H "Content-Type: application/json" \
  -d '{
    "projectPath": "test-repo",
    "scanType": "FULL"
  }'
```

### 3. Verify Results

Should find vulnerabilities in BOTH `.ts` and `.py` files:
- [ ] XSS in TypeScript
- [ ] NoSQL injection in TypeScript
- [ ] Path traversal in TypeScript
- [ ] SQL injection in Python
- [ ] Insecure deserialization in Python

## Summary

Your scanner **already supports** TypeScript files. The fix is to:

1. ✅ **Ensure fileList includes .ts/.tsx files** — Check file discovery logic
2. ✅ **Add language-specific security rules** — Enhance LLM prompt
3. ✅ **Test with multi-language repository** — Verify both languages scanned
4. ✅ **Enable per-language analyzers** — Implement language-aware checks

The code is ready — just verify the file discovery and enhance the prompts!
