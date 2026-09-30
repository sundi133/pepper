import { Dependency, DependencyParser } from "../../types";

/** Attributes of an XML start tag, keys lower-cased. */
function attributes(tag: string): Map<string, string> {
  const out = new Map<string, string>();
  for (const m of tag.matchAll(/([\w.:-]+)\s*=\s*"([^"]*)"/g)) out.set(m[1].toLowerCase(), m[2]);
  return out;
}

/** MSBuild properties defined in this file (`<PropertyGroup><Name>value</Name>`). */
function msbuildProperties(xml: string): Map<string, string> {
  const props = new Map<string, string>();
  for (const group of xml.matchAll(/<PropertyGroup[^>]*>([\s\S]*?)<\/PropertyGroup>/gi)) {
    for (const m of group[1].matchAll(/<([\w.]+)>\s*([^<]*?)\s*<\/\1>/g)) props.set(m[1].toLowerCase(), m[2]);
  }
  return props;
}

/** Resolve `$(Name)`; undefined when it can't be (defined elsewhere). */
function resolveVersion(value: string | undefined, props: Map<string, string>): string | undefined {
  if (!value) return undefined;
  const v = value.replace(/\$\(([\w.]+)\)/g, (whole, name: string) => props.get(name.toLowerCase()) ?? whole).trim();
  if (!v || v.includes("$(") || /^[[(]/.test(v) || v.includes("*")) return undefined; // ranges / floating
  return v;
}

/**
 * `<Tag Include="X" Version="1.0" />`, `<Tag Version="1.0" Include="X">`, and
 * the child-element form `<Tag Include="X"><Version>1.0</Version></Tag>`.
 */
function packageElements(xml: string, tag: string): Array<{ name: string; version?: string }> {
  const out: Array<{ name: string; version?: string }> = [];
  const re = new RegExp(`<${tag}\\b([^>]*?)(/>|>([\\s\\S]*?)</${tag}>)`, "gi");
  for (const m of xml.matchAll(re)) {
    const attrs = attributes(m[1]);
    const name = attrs.get("include") ?? attrs.get("update");
    if (!name) continue;
    const child = m[3]?.match(/<(?:Version|VersionOverride)>\s*([^<]+?)\s*<\/(?:Version|VersionOverride)>/i)?.[1];
    out.push({ name, version: attrs.get("versionoverride") ?? attrs.get("version") ?? child });
  }
  return out;
}

/**
 * Parser for .NET .csproj / .fsproj / .vbproj files: PackageReference items.
 * With central package management the version lives in
 * Directory.Packages.props instead (parsed separately), so references without
 * a version are skipped here.
 */
export const csprojParser: DependencyParser = {
  filePatterns: [], // Matched by extension in parseDependencies
  ecosystem: "NuGet",
  parse(content: string): Dependency[] {
    const xml = content.replace(/<!--[\s\S]*?-->/g, "");
    const props = msbuildProperties(xml);
    const deps: Dependency[] = [];
    for (const ref of packageElements(xml, "PackageReference")) {
      const version = resolveVersion(ref.version, props);
      if (version) deps.push({ name: ref.name, version, ecosystem: "NuGet" });
    }
    return deps;
  },
};

/**
 * Central package management (`Directory.Packages.props`): the versions every
 * project in the repo uses.
 */
export const directoryPackagesPropsParser: DependencyParser = {
  filePatterns: ["Directory.Packages.props"],
  ecosystem: "NuGet",
  parse(content: string): Dependency[] {
    const xml = content.replace(/<!--[\s\S]*?-->/g, "");
    const props = msbuildProperties(xml);
    const deps: Dependency[] = [];
    for (const tag of ["PackageVersion", "GlobalPackageReference"]) {
      for (const ref of packageElements(xml, tag)) {
        const version = resolveVersion(ref.version, props);
        if (version) deps.push({ name: ref.name, version, ecosystem: "NuGet" });
      }
    }
    return deps;
  },
};

/**
 * NuGet lock file (`packages.lock.json`, `RestorePackagesWithLockFile`):
 * resolved versions for every target framework, including transitive ones.
 */
export const packagesLockJsonParser: DependencyParser = {
  filePatterns: ["packages.lock.json"],
  ecosystem: "NuGet",
  parse(content: string): Dependency[] {
    let lock: { dependencies?: Record<string, Record<string, { type?: string; resolved?: string }>> };
    try {
      lock = JSON.parse(content);
    } catch {
      return [];
    }
    const deps: Dependency[] = [];
    const seen = new Set<string>();
    for (const packages of Object.values(lock.dependencies ?? {})) {
      for (const [name, info] of Object.entries(packages ?? {})) {
        if (!info?.resolved || info.type === "Project") continue; // project-to-project reference
        const key = `${name.toLowerCase()}@${info.resolved}`;
        if (seen.has(key)) continue;
        seen.add(key);
        deps.push({ name, version: info.resolved, ecosystem: "NuGet" });
      }
    }
    return deps;
  },
};

/**
 * Parser for NuGet packages.config (older .NET format)
 */
export const packagesConfigParser: DependencyParser = {
  filePatterns: ["packages.config"],
  ecosystem: "NuGet",
  parse(content: string): Dependency[] {
    const deps: Dependency[] = [];
    for (const m of content.matchAll(/<package\b([^>]*?)\/?>/gi)) {
      const attrs = attributes(m[1]);
      const id = attrs.get("id");
      const version = attrs.get("version");
      if (id && version) {
        deps.push({ name: id, version, ecosystem: "NuGet", isDev: attrs.get("developmentdependency") === "true" });
      }
    }
    return deps;
  },
};
