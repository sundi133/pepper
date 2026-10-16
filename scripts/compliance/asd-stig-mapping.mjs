/**
 * Pepper's reviewed CWE crosswalk for the DISA Application Security and
 * Development STIG, keyed by Vuln ID. build-frameworks.mjs folds it into
 * compliance/DISA_ASD_STIG.json and fails if an entry's STIG ID no longer
 * matches the source, so a renumbered requirement can't silently pick up the
 * wrong mapping.
 *
 * Only requirements a code weakness can evidence are listed. Every other
 * requirement (process, documentation, deployment, runtime configuration,
 * policy values) is reported as not assessable by static analysis.
 *
 *   assessable  the requirement is about the weakness class itself, so a
 *               clean scan is meaningful evidence (e.g. SQL injection).
 *   partial     the weakness shows the requirement is not met, but meeting it
 *               also needs things code scanning can't see (thresholds,
 *               FIPS validation, deployment, policy).
 *
 * A CWE appears under more than one requirement only when a finding of that
 * weakness violates each of them (CWE-20, CWE-613, CWE-776).
 */
export const ASD_STIG_CWE_MAP = {
  // Sessions
  "V-222389": { stigId: "APSC-DV-000070", coverage: "partial", cwe: [613] }, // idle session timeout (15 min is configuration)
  "V-222578": { stigId: "APSC-DV-002240", coverage: "partial", cwe: [613] }, // destroy session ID on logoff
  "V-222575": { stigId: "APSC-DV-002210", coverage: "assessable", cwe: [1004] }, // HttpOnly session cookies
  "V-222576": { stigId: "APSC-DV-002220", coverage: "assessable", cwe: [614] }, // Secure session cookies
  "V-222579": { stigId: "APSC-DV-002250", coverage: "assessable", cwe: [384] }, // session fixation
  "V-222581": { stigId: "APSC-DV-002270", coverage: "partial", cwe: [598] }, // session IDs in URLs

  // Access control and privileges
  "V-222425": { stigId: "APSC-DV-000460", coverage: "partial", cwe: [284, 285, 425, 566, 639, 862, 863] }, // enforce approved authorizations
  "V-222429": { stigId: "APSC-DV-000500", coverage: "partial", cwe: [269, 732] }, // privileged functions; check covers file permissions
  "V-222430": { stigId: "APSC-DV-000510", coverage: "partial", cwe: [250, 272] }, // execute without excessive permissions (e.g. as root)

  // Authentication and credentials
  "V-222432": { stigId: "APSC-DV-000530", coverage: "partial", cwe: [307] }, // lockout after failed logons (3 / 15 min is configuration)
  "V-222522": { stigId: "APSC-DV-001540", coverage: "partial", cwe: [287, 288, 290, 305, 306, 1390] }, // identify and authenticate users
  "V-222536": { stigId: "APSC-DV-001680", coverage: "partial", cwe: [521] }, // password policy (15-character minimum)
  "V-222542": { stigId: "APSC-DV-001740", coverage: "assessable", cwe: [256, 257, 261, 759, 760, 916] }, // store only password hashes
  "V-222543": { stigId: "APSC-DV-001750", coverage: "partial", cwe: [523] }, // transmit passwords only encrypted
  "V-222548": { stigId: "APSC-DV-001795", coverage: "partial", cwe: [620, 640] }, // password changeable only by owner or admin
  "V-222550": { stigId: "APSC-DV-001810", coverage: "partial", cwe: [295, 296, 297, 298, 299, 599] }, // certificate path validation
  "V-222554": { stigId: "APSC-DV-001850", coverage: "partial", cwe: [549] }, // no cleartext password display
  "V-222642": { stigId: "APSC-DV-003110", coverage: "assessable", cwe: [259, 260, 321, 798] }, // no embedded authentication data
  "V-222662": { stigId: "APSC-DV-003280", coverage: "partial", cwe: [1392, 1393] }, // default passwords changed

  // Cryptography and data protection
  "V-222571": { stigId: "APSC-DV-002030", coverage: "partial", cwe: [328] }, // approved hashing (module validation not visible in code)
  "V-222572": { stigId: "APSC-DV-002040", coverage: "partial", cwe: [323, 326, 327, 329, 330, 331, 338, 780] }, // approved crypto and RNG
  "V-222589": { stigId: "APSC-DV-002350", coverage: "partial", cwe: [311, 312, 313, 922] }, // encrypt stored information
  "V-222596": { stigId: "APSC-DV-002440", coverage: "partial", cwe: [5, 319, 757] }, // protect transmitted information
  "V-222444": { stigId: "APSC-DV-000650", coverage: "assessable", cwe: [532] }, // no sensitive data in logs
  "V-222600": { stigId: "APSC-DV-002480", coverage: "partial", cwe: [200, 203, 204, 215, 497, 548] }, // no unnecessary information disclosure

  // Input handling (CCI-001310 / SI-10 and CCI-002754 / SI-10(3))
  "V-222602": { stigId: "APSC-DV-002490", coverage: "assessable", cwe: [79, 80, 81, 83, 84, 85, 86, 87] }, // XSS
  "V-222603": { stigId: "APSC-DV-002500", coverage: "assessable", cwe: [352] }, // CSRF
  // The STIG's discussion lists eval / exec / Class.forName alongside shell calls.
  "V-222604": { stigId: "APSC-DV-002510", coverage: "assessable", cwe: [77, 78, 88, 94, 95, 470] }, // command injection
  "V-222605": { stigId: "APSC-DV-002520", coverage: "partial", cwe: [22, 23, 36, 41, 176, 180, 182] }, // canonical representation (path equivalence)
  // Injection classes without a requirement of their own.
  "V-222606": { stigId: "APSC-DV-002530", coverage: "assessable", cwe: [20, 74, 90, 93, 113, 117, 601, 917, 918, 943, 1236, 1336] }, // validate all input
  "V-222607": { stigId: "APSC-DV-002540", coverage: "assessable", cwe: [89, 564] }, // SQL injection
  "V-222608": { stigId: "APSC-DV-002550", coverage: "assessable", cwe: [91, 611, 643, 652, 776, 827] }, // XML-oriented attacks (check lists XPath injection, XML DoS)
  // Unsafe handling of untrusted structured input.
  "V-222609": { stigId: "APSC-DV-002560", coverage: "assessable", cwe: [20, 129, 434, 502, 915, 1284, 1287, 1321] }, // input handling vulnerabilities
  "V-222612": { stigId: "APSC-DV-002590", coverage: "assessable", cwe: [119, 120, 121, 122, 125, 131, 134, 190, 191, 680, 787, 805] }, // overflows incl. integer and format string
  "V-222593": { stigId: "APSC-DV-002390", coverage: "assessable", cwe: [776] }, // XML DoS
  "V-222594": { stigId: "APSC-DV-002400", coverage: "partial", cwe: [400, 674, 770, 1333] }, // DoS resistance

  // Errors, failure and concurrency
  "V-222610": { stigId: "APSC-DV-002570", coverage: "assessable", cwe: [209, 210, 211, 537, 550] }, // error messages reveal nothing exploitable
  "V-222656": { stigId: "APSC-DV-003235", coverage: "assessable", cwe: [248, 252, 390, 391, 396, 397, 703, 754, 755] }, // error handling vulnerabilities
  "V-222585": { stigId: "APSC-DV-002310", coverage: "partial", cwe: [455, 636] }, // fail to a secure state
  "V-222567": { stigId: "APSC-DV-001995", coverage: "assessable", cwe: [362, 364, 366, 367] }, // race conditions

  // Components and configuration
  "V-222513": { stigId: "APSC-DV-001430", coverage: "partial", cwe: [494] }, // verify signatures before installing components
  "V-222518": { stigId: "APSC-DV-001500", coverage: "partial", cwe: [489] }, // disable non-essential capabilities (debug code)
  "V-222614": { stigId: "APSC-DV-002630", coverage: "partial", cwe: [1395] }, // security patches up to date
  "V-222658": { stigId: "APSC-DV-003240", coverage: "partial", cwe: [1104] }, // products supported (unmaintained components)
};
