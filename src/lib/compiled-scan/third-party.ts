/**
 * Third-party code inside compiled artifacts.
 *
 * A JAR, APK or published .NET folder carries its dependencies with it. Those
 * are the SCA scanner's business (known vulnerable versions), not something
 * to review line by line as if the customer wrote them: decompiling them
 * multiplies cost and buries the application's own findings. So by default the
 * compiled scan skips artifacts in dependency folders, well-known library
 * assemblies, and well-known library packages inside an artifact.
 */

/** Folders that hold dependencies rather than the application (path segments). */
export const DEPENDENCY_DIRS = new Set([
  "lib",
  "libs",
  "node_modules",
  "bower_components",
  "jspm_packages",
  "packages",
  ".nuget",
  ".m2",
  ".gradle",
  ".ivy2",
  ".cache",
  "vendor",
  "third_party",
  "third-party",
  "thirdparty",
  "Pods",
  "Carthage",
]);

/** Multi-segment dependency folders inside Java archives and web apps. */
const DEPENDENCY_PATH_PATTERNS = [/(^|\/)WEB-INF\/lib\//i, /(^|\/)BOOT-INF\/lib\//i, /(^|\/)APP-INF\/lib\//i];

/** True when a repository-relative path lies in a dependency folder. */
export function isInDependencyDir(relPath: string): boolean {
  const norm = relPath.replace(/\\/g, "/");
  if (DEPENDENCY_PATH_PATTERNS.some((re) => re.test(norm))) return true;
  const dirs = norm.split("/").slice(0, -1);
  return dirs.some((d) => DEPENDENCY_DIRS.has(d));
}

/**
 * Well-known library packages (JVM / Android) and namespaces (.NET), as path
 * prefixes of decompiled source ("com/google/" matches com.google.*).
 */
export const THIRD_PARTY_PACKAGES = [
  // Platform and language runtimes
  "android",
  "androidx",
  "java",
  "javax",
  "jakarta",
  "kotlin",
  "kotlinx",
  "scala",
  "groovy",
  "sun",
  "com/sun",
  "jdk",
  "dalvik",
  // Google / Android ecosystem
  "com/google",
  "com/android",
  "org/chromium",
  "com/crashlytics",
  "io/fabric",
  "com/firebase",
  // Common Java / Android libraries
  "org/apache",
  "org/jetbrains",
  "org/intellij",
  "org/springframework",
  "org/hibernate",
  "org/slf4j",
  "ch/qos/logback",
  "org/apache/logging",
  "com/fasterxml",
  "com/squareup",
  "okhttp3",
  "okio",
  "retrofit2",
  "io/reactivex",
  "rx",
  "io/netty",
  "io/grpc",
  "com/facebook",
  "com/bumptech/glide",
  "dagger",
  "org/json",
  "org/bouncycastle",
  "org/spongycastle",
  "org/joda",
  "com/jakewharton",
  "timber",
  "io/sentry",
  "org/greenrobot",
  "com/airbnb/lottie",
  "net/sqlcipher",
  "org/eclipse",
  "org/glassfish",
  "org/jboss",
  "org/aspectj",
  "org/yaml",
  "org/codehaus",
  "org/objectweb",
  "com/esotericsoftware",
  "org/junit",
  "junit",
  "org/mockito",
  "org/hamcrest",
  "org/checkerframework",
  "javassist",
  "net/bytebuddy",
  "com/microsoft",
  "io/micrometer",
  "io/swagger",
  "reactor",
  "org/reactivestreams",
  "com/zaxxer",
  "org/postgresql",
  "com/mysql",
  "org/h2",
  "org/xml",
  "org/w3c",
  "lombok",
  // .NET namespaces (ILSpy writes nested namespace directories)
  "System",
  "Microsoft",
  "Newtonsoft",
  "MS/Internal",
  "Mono",
];

export interface PackageFilter {
  skipThirdParty: boolean;
  excludePackages: string[];
  includePackages: string[];
}

function hasPrefix(innerPath: string, prefix: string): boolean {
  return innerPath === prefix || innerPath.startsWith(`${prefix}/`);
}

/**
 * Package-path prefix of a decompiled file: strips a web/boot archive's class
 * folder so "WEB-INF/classes/org/apache/X.java" is checked as "org/apache/X.java".
 */
export function packagePathOf(innerPath: string): string {
  return innerPath.replace(/\\/g, "/").replace(/^(?:WEB-INF|BOOT-INF|APP-INF)\/classes\//i, "");
}

/** Whether a decompiled file (path inside its artifact) belongs to a skipped package. */
export function isThirdPartyPackage(innerPath: string, filter: PackageFilter): boolean {
  const pkg = packagePathOf(innerPath);
  if (filter.includePackages.some((p) => hasPrefix(pkg, p))) return false;
  if (filter.excludePackages.some((p) => hasPrefix(pkg, p))) return true;
  if (!filter.skipThirdParty) return false;
  return THIRD_PARTY_PACKAGES.some((p) => hasPrefix(pkg, p));
}

function escapeRegex(s: string): string {
  return s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

/**
 * Java regex for Vineflower's --excluded-classes (matched against the class's
 * fully qualified name, dotted or slashed) so excluded packages are never
 * decompiled at all. Null when nothing is excluded.
 */
export function vineflowerExcludeRegex(filter: PackageFilter): string | null {
  const excluded = [...filter.excludePackages, ...(filter.skipThirdParty ? THIRD_PARTY_PACKAGES : [])]
    // Only JVM-style lowercase package roots: .NET namespaces never occur here.
    .filter((p) => /^[a-z]/.test(p));
  if (excluded.length === 0) return null;
  const sep = "[./]";
  const toPattern = (p: string) => p.split("/").map(escapeRegex).join(sep) + sep;
  const include = filter.includePackages.map(toPattern);
  const lookahead = include.length ? `(?!(?:${include.join("|")}))` : "";
  return `^${lookahead}(?:${excluded.map(toPattern).join("|")}).*`;
}

/** Well-known library assemblies shipped next to a .NET application. */
const THIRD_PARTY_ASSEMBLY_PATTERNS = [
  /^System(\..+)?\.dll$/i,
  /^Microsoft\..+\.(dll|exe)$/i,
  /^mscorlib\.dll$/i,
  /^netstandard\.dll$/i,
  /^WindowsBase\.dll$/i,
  /^Presentation(Core|Framework).*\.dll$/i,
  /^Newtonsoft\..+\.dll$/i,
  /^NLog(\..+)?\.dll$/i,
  /^Serilog(\..+)?\.dll$/i,
  /^log4net\.dll$/i,
  /^Dapper(\..+)?\.dll$/i,
  /^AutoMapper(\..+)?\.dll$/i,
  /^EntityFramework(\..+)?\.dll$/i,
  /^Npgsql(\..+)?\.dll$/i,
  /^MySql(Connector|\.Data).*\.dll$/i,
  /^Oracle\..+\.dll$/i,
  /^Castle\..+\.dll$/i,
  /^Autofac(\..+)?\.dll$/i,
  /^Polly(\..+)?\.dll$/i,
  /^FluentValidation(\..+)?\.dll$/i,
  /^MediatR(\..+)?\.dll$/i,
  /^Swashbuckle\..+\.dll$/i,
  /^StackExchange\..+\.dll$/i,
  /^Google\..+\.dll$/i,
  /^Grpc(\..+)?\.dll$/i,
  /^Azure(\..+)?\.dll$/i,
  /^AWSSDK\..+\.dll$/i,
  /^BouncyCastle.*\.dll$/i,
  /^(nunit|xunit|Moq|FluentAssertions)(\..+)?\.dll$/i,
  /^SQLitePCLRaw\..+\.dll$/i,
  /^Humanizer\.dll$/i,
  /^RestSharp\.dll$/i,
  /^Hangfire(\..+)?\.dll$/i,
  /^MongoDB\..+\.dll$/i,
  /^Quartz(\..+)?\.dll$/i,
  /^Owin\.dll$/i,
  /^Antlr\d*(\..+)?\.dll$/i,
  /^WebGrease\.dll$/i,
  /^DotNetOpenAuth.*\.dll$/i,
];

export function isThirdPartyAssembly(fileName: string, filter: PackageFilter): boolean {
  const asNamespace = fileName.replace(/\.(dll|exe)$/i, "").replace(/\./g, "/");
  if (filter.includePackages.some((p) => hasPrefix(asNamespace, p))) return false;
  if (filter.excludePackages.some((p) => hasPrefix(asNamespace, p))) return true;
  if (!filter.skipThirdParty) return false;
  return THIRD_PARTY_ASSEMBLY_PATTERNS.some((re) => re.test(fileName));
}
