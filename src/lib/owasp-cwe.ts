/**
 * Maps CWE identifiers to OWASP Top 10 2021 categories for reporting.
 * https://owasp.org/Top10/
 */

export interface OwaspMapping {
  /** e.g. "A03:2021" */
  id: string;
  /** Short category name */
  name: string;
}

const CWE_NORMALIZE = /^CWE-(\d+)/i;

export function normalizeCweId(raw?: string | null): string | undefined {
  if (!raw?.trim()) return undefined;
  const m = raw.trim().match(CWE_NORMALIZE);
  return m ? `CWE-${m[1]}` : raw.trim();
}

/** Primary CWE → OWASP 2021 mapping (representative; overlaps exist). */
const CWE_TO_OWASP: Record<string, OwaspMapping> = {
  // A01 Broken Access Control
  "285": { id: "A01:2021", name: "Broken Access Control" },
  "639": { id: "A01:2021", name: "Broken Access Control" },
  "862": { id: "A01:2021", name: "Broken Access Control" },
  "863": { id: "A01:2021", name: "Broken Access Control" },
  "652": { id: "A01:2021", name: "Broken Access Control" },
  // A02 Cryptographic Failures
  "327": { id: "A02:2021", name: "Cryptographic Failures" },
  "328": { id: "A02:2021", name: "Cryptographic Failures" },
  "338": { id: "A02:2021", name: "Cryptographic Failures" },
  "757": { id: "A02:2021", name: "Cryptographic Failures" },
  "798": { id: "A02:2021", name: "Cryptographic Failures" },
  "321": { id: "A02:2021", name: "Cryptographic Failures" },
  // A03 Injection
  "74": { id: "A03:2021", name: "Injection" },
  "77": { id: "A03:2021", name: "Injection" },
  "78": { id: "A03:2021", name: "Injection" },
  "79": { id: "A03:2021", name: "Injection" },
  "89": { id: "A03:2021", name: "Injection" },
  "90": { id: "A03:2021", name: "Injection" },
  "91": { id: "A03:2021", name: "Injection" },
  "93": { id: "A03:2021", name: "Injection" },
  "94": { id: "A03:2021", name: "Injection" },
  "95": { id: "A03:2021", name: "Injection" },
  "113": { id: "A03:2021", name: "Injection" },
  "116": { id: "A03:2021", name: "Injection" },
  "643": { id: "A03:2021", name: "Injection" },
  "917": { id: "A03:2021", name: "Injection" },
  "943": { id: "A03:2021", name: "Injection" },
  // A04 Insecure Design
  "209": { id: "A04:2021", name: "Insecure Design" },
  "213": { id: "A04:2021", name: "Insecure Design" },
  "656": { id: "A04:2021", name: "Insecure Design" },
  // A05 Security Misconfiguration
  "16": { id: "A05:2021", name: "Security Misconfiguration" },
  "2": { id: "A05:2021", name: "Security Misconfiguration" },
  "11": { id: "A05:2021", name: "Security Misconfiguration" },
  "15": { id: "A05:2021", name: "Security Misconfiguration" },
  "260": { id: "A05:2021", name: "Security Misconfiguration" },
  "311": { id: "A05:2021", name: "Security Misconfiguration" },
  "319": { id: "A05:2021", name: "Security Misconfiguration" },
  "614": { id: "A05:2021", name: "Security Misconfiguration" },
  "756": { id: "A05:2021", name: "Security Misconfiguration" },
  // A06 Vulnerable Components
  "1104": { id: "A06:2021", name: "Vulnerable and Outdated Components" },
  // A07 Identification / Auth Failures
  "287": { id: "A07:2021", name: "Identification and Authentication Failures" },
  "288": { id: "A07:2021", name: "Identification and Authentication Failures" },
  "290": { id: "A07:2021", name: "Identification and Authentication Failures" },
  "294": { id: "A07:2021", name: "Identification and Authentication Failures" },
  "307": { id: "A07:2021", name: "Identification and Authentication Failures" },
  "640": { id: "A07:2021", name: "Identification and Authentication Failures" },
  // A08 Software / Data Integrity
  "345": { id: "A08:2021", name: "Software and Data Integrity Failures" },
  "353": { id: "A08:2021", name: "Software and Data Integrity Failures" },
  "426": { id: "A08:2021", name: "Software and Data Integrity Failures" },
  "502": { id: "A08:2021", name: "Software and Data Integrity Failures" },
  "506": { id: "A08:2021", name: "Software and Data Integrity Failures" },
  "829": { id: "A08:2021", name: "Software and Data Integrity Failures" },
  // A09 Logging / Monitoring
  "117": { id: "A09:2021", name: "Security Logging and Monitoring Failures" },
  "223": { id: "A09:2021", name: "Security Logging and Monitoring Failures" },
  "532": { id: "A09:2021", name: "Security Logging and Monitoring Failures" },
  "778": { id: "A09:2021", name: "Security Logging and Monitoring Failures" },
  // A10 SSRF
  "918": { id: "A10:2021", name: "Server-Side Request Forgery (SSRF)" },
  // Common extras
  "22": { id: "A01:2021", name: "Broken Access Control" },
  "352": { id: "A01:2021", name: "Broken Access Control" },
  "601": { id: "A01:2021", name: "Broken Access Control" },
  "611": { id: "A03:2021", name: "Injection" },
  "942": { id: "A05:2021", name: "Security Misconfiguration" },
  "1321": { id: "A08:2021", name: "Software and Data Integrity Failures" },
};

export function cweToOwasp(cweId?: string | null): OwaspMapping | undefined {
  const norm = normalizeCweId(cweId);
  if (!norm) return undefined;
  const num = norm.replace(/^CWE-/i, "");
  return CWE_TO_OWASP[num];
}

/** Keyword fallback when CWE is missing or unmapped */
export function inferOwaspFromText(text: string): OwaspMapping | undefined {
  const t = text.toLowerCase();
  if (/sql\s*inject|nosql\s*inject|cwe-89|cwe-943/.test(t))
    return { id: "A03:2021", name: "Injection" };
  if (/xss|cwe-79|cross.site/.test(t))
    return { id: "A03:2021", name: "Injection" };
  if (/command\s*inject|rce|cwe-78/.test(t))
    return { id: "A03:2021", name: "Injection" };
  if (/path\s*traversal|directory\s*traversal|cwe-22/.test(t))
    return { id: "A01:2021", name: "Broken Access Control" };
  if (/ssrf|cwe-918/.test(t))
    return { id: "A10:2021", name: "Server-Side Request Forgery (SSRF)" };
  if (/xxe|cwe-611/.test(t))
    return { id: "A03:2021", name: "Injection" };
  if (/csrf|cwe-352/.test(t))
    return { id: "A01:2021", name: "Broken Access Control" };
  if (/open\s*redirect|cwe-601/.test(t))
    return { id: "A01:2021", name: "Broken Access Control" };
  if (/deserial|cwe-502/.test(t))
    return { id: "A08:2021", name: "Software and Data Integrity Failures" };
  if (/cors|cwe-942/.test(t))
    return { id: "A05:2021", name: "Security Misconfiguration" };
  if (/idor|bola|access\s*control|cwe-639|cwe-285|cwe-862|cwe-863/.test(t))
    return { id: "A01:2021", name: "Broken Access Control" };
  if (/secret|credential|password|token|cwe-798/.test(t))
    return { id: "A02:2021", name: "Cryptographic Failures" };
  if (/cookie|session|jwt|auth|cwe-287/.test(t))
    return { id: "A07:2021", name: "Identification and Authentication Failures" };
  if (/dependency|cve-|sca|supply\s*chain/.test(t))
    return { id: "A06:2021", name: "Vulnerable and Outdated Components" };
  return undefined;
}
