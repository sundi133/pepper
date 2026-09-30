import { Dependency, DependencyParser } from "../../types";

/** Text of the first `<tag>…</tag>` in `xml`, trimmed. */
function tagText(xml: string, tag: string): string | undefined {
  const m = xml.match(new RegExp(`<${tag}>\\s*([^<]*?)\\s*</${tag}>`));
  return m?.[1];
}

/** Drop whole `<tag>…</tag>` blocks (non-greedy, may repeat). */
function withoutBlocks(xml: string, tags: string[]): string {
  let out = xml;
  for (const tag of tags) out = out.replace(new RegExp(`<${tag}(\\s[^>]*)?>[\\s\\S]*?</${tag}>`, "g"), "");
  return out;
}

/**
 * Resolve `${name}` references from the POM's own `<properties>` and project
 * coordinates. Returns undefined when something can't be resolved (parent POM
 * or build-time property) — better to skip than to query a bogus version.
 */
function resolveProps(value: string, props: Map<string, string>): string | undefined {
  let v = value;
  for (let i = 0; i < 5 && v.includes("${"); i++) {
    v = v.replace(/\$\{([^}]+)\}/g, (whole, name: string) => props.get(name.trim()) ?? whole);
  }
  return v.includes("${") ? undefined : v.trim();
}

export const pomXmlParser: DependencyParser = {
  filePatterns: ["pom.xml"],
  ecosystem: "Maven",
  parse(content: string): Dependency[] {
    const xml = content.replace(/<!--[\s\S]*?-->/g, "");
    const deps: Dependency[] = [];

    const props = new Map<string, string>();
    const propsBlock = xml.match(/<properties>([\s\S]*?)<\/properties>/)?.[1] ?? "";
    for (const m of propsBlock.matchAll(/<([A-Za-z0-9_.-]+)>\s*([^<]*?)\s*<\/\1>/g)) props.set(m[1], m[2]);
    // The project's own coordinates, ignoring nested parent / dependency / build blocks.
    const top = withoutBlocks(xml, ["parent", "dependencies", "dependencyManagement", "build", "profiles", "reporting", "properties"]);
    const parentVersion = tagText(xml.match(/<parent>([\s\S]*?)<\/parent>/)?.[1] ?? "", "version");
    const projectVersion = tagText(top, "version") ?? parentVersion;
    const projectGroup = tagText(top, "groupId") ?? tagText(xml.match(/<parent>([\s\S]*?)<\/parent>/)?.[1] ?? "", "groupId");
    for (const [k, v] of [
      ["project.version", projectVersion],
      ["pom.version", projectVersion],
      ["version", projectVersion],
      ["project.parent.version", parentVersion],
      ["project.groupId", projectGroup],
    ] as const) {
      if (v && !props.has(k)) props.set(k, v);
    }

    // Plugins declare dependencies too, but those are build tooling.
    const scope = withoutBlocks(xml, ["plugins", "pluginManagement"]);
    for (const block of scope.matchAll(/<dependency>([\s\S]*?)<\/dependency>/g)) {
      const body = block[1];
      const groupId = resolveProps(tagText(body, "groupId") ?? "", props);
      const artifactId = resolveProps(tagText(body, "artifactId") ?? "", props);
      const rawVersion = tagText(body, "version");
      const depScope = tagText(body, "scope");
      // BOM imports (<type>pom</type><scope>import</scope>) are version tables, not libraries.
      if (depScope === "import") continue;
      if (!groupId || !artifactId || !rawVersion) continue; // version managed by a parent
      const version = resolveProps(rawVersion, props);
      if (!version || /^[[(]/.test(version)) continue; // unresolvable or a version range
      deps.push({
        name: `${groupId}:${artifactId}`,
        version,
        ecosystem: "Maven",
        isDev: depScope === "test" || depScope === "provided",
      });
    }
    return deps;
  },
};

const GRADLE_CONFIGURATIONS = [
  "implementation",
  "api",
  "compile",
  "compileOnly",
  "runtime",
  "runtimeOnly",
  "annotationProcessor",
  "kapt",
  "ksp",
  "testImplementation",
  "testCompileOnly",
  "testRuntimeOnly",
  "androidTestImplementation",
  "debugImplementation",
  "releaseImplementation",
].join("|");

/** `def x = '1.0'`, `val x = "1.0"`, `ext.x = '1.0'`, `x = "1.0"` (in ext {}) → x. */
function gradleVariables(content: string): Map<string, string> {
  const vars = new Map<string, string>();
  for (const m of content.matchAll(/(?:^|[\s{;])(?:def\s+|val\s+|var\s+|ext\.|extra\[")?([A-Za-z_][\w.]*)"?\]?\s*=\s*["']([^"'$\s]+)["']/gm)) {
    vars.set(m[1], m[2]);
    vars.set(m[1].split(".").pop()!, m[2]);
  }
  return vars;
}

function resolveGradleVersion(version: string, vars: Map<string, string>): string | undefined {
  const v = version.replace(/\$\{([\w.]+)\}|\$([\w.]+)/g, (whole, a?: string, b?: string) => {
    const name = (a ?? b)!;
    return vars.get(name) ?? vars.get(name.split(".").pop()!) ?? whole;
  });
  if (v.includes("$") || !/^[\w.+-]+$/.test(v)) return undefined;
  return v;
}

export const buildGradleParser: DependencyParser = {
  filePatterns: ["build.gradle", "build.gradle.kts"],
  ecosystem: "Maven",
  parse(content: string): Dependency[] {
    const deps: Dependency[] = [];
    const vars = gradleVariables(content);
    const push = (config: string, group: string, name: string, rawVersion: string) => {
      const version = resolveGradleVersion(rawVersion.trim(), vars);
      if (!version) return;
      deps.push({
        name: `${group.trim()}:${name.trim()}`,
        version,
        ecosystem: "Maven",
        isDev: /test|compileOnly/i.test(config),
      });
    };

    // implementation 'g:a:v' · implementation("g:a:v") · implementation "g:a:v:classifier@aar"
    const stringForm = new RegExp(`\\b(${GRADLE_CONFIGURATIONS})\\s*\\(?\\s*["']([^:"'\\s]+):([^:"'\\s]+):([^:"'@\\s]+)[^"']*["']`, "g");
    for (const m of content.matchAll(stringForm)) push(m[1], m[2], m[3], m[4]);

    // implementation group: 'g', name: 'a', version: 'v'  ·  implementation(group = "g", name = "a", version = "v")
    const namedForm = new RegExp(
      `\\b(${GRADLE_CONFIGURATIONS})\\s*\\(?\\s*group\\s*[:=]\\s*["']([^"']+)["']\\s*,\\s*name\\s*[:=]\\s*["']([^"']+)["']\\s*,\\s*version\\s*[:=]\\s*["']([^"']+)["']`,
      "g",
    );
    for (const m of content.matchAll(namedForm)) push(m[1], m[2], m[3], m[4]);

    return deps;
  },
};

/**
 * Gradle dependency lock state (`gradle.lockfile`): exact resolved versions
 * for every configuration, including transitive dependencies.
 *   com.google.guava:guava:31.1-jre=compileClasspath,runtimeClasspath
 */
export const gradleLockfileParser: DependencyParser = {
  filePatterns: ["gradle.lockfile", "buildscript-gradle.lockfile"],
  ecosystem: "Maven",
  parse(content: string, filePath: string): Dependency[] {
    if (filePath.endsWith("buildscript-gradle.lockfile")) return []; // build plugins
    const deps: Dependency[] = [];
    for (const raw of content.split("\n")) {
      const line = raw.trim();
      if (!line || line.startsWith("#") || line.startsWith("empty=")) continue;
      const m = line.match(/^([^:\s]+):([^:\s]+):([^=\s]+)=(.*)$/);
      if (!m) continue;
      const configs = m[4].split(",").map((c) => c.trim()).filter(Boolean);
      deps.push({
        name: `${m[1]}:${m[2]}`,
        version: m[3],
        ecosystem: "Maven",
        isDev: configs.length > 0 && configs.every((c) => /^test|AndroidTest|UnitTest/i.test(c)),
      });
    }
    return deps;
  },
};

/**
 * Gradle version catalog (`gradle/libs.versions.toml`), the default for new
 * Android / Kotlin projects: [versions] name = "1.0" and [libraries] entries
 *   alias = "g:a:1.0"
 *   alias = { module = "g:a", version.ref = "name" }
 *   alias = { group = "g", name = "a", version = "1.0" }
 */
export const versionCatalogParser: DependencyParser = {
  filePatterns: ["libs.versions.toml"],
  ecosystem: "Maven",
  parse(content: string): Dependency[] {
    const versions = new Map<string, string>();
    const libraries: string[] = [];
    let section = "";
    for (const raw of content.split("\n")) {
      const line = raw.replace(/#.*$/, "").trim();
      if (!line) continue;
      const header = line.match(/^\[([\w-]+)\]$/);
      if (header) {
        section = header[1];
        continue;
      }
      if (section === "versions") {
        const m = line.match(/^([\w.-]+)\s*=\s*"([^"]+)"/);
        if (m) versions.set(m[1], m[2]);
      } else if (section === "libraries") {
        libraries.push(line);
      }
    }
    const deps: Dependency[] = [];
    for (const line of libraries) {
      const str = line.match(/^[\w.-]+\s*=\s*"([^:"]+):([^:"]+):([^:"]+)"/);
      if (str) {
        deps.push({ name: `${str[1]}:${str[2]}`, version: str[3], ecosystem: "Maven" });
        continue;
      }
      const moduleCoords = line.match(/module\s*=\s*"([^:"]+):([^"]+)"/);
      const group = line.match(/group\s*=\s*"([^"]+)"/)?.[1];
      const name = line.match(/\bname\s*=\s*"([^"]+)"/)?.[1];
      const coords = moduleCoords ? [moduleCoords[1], moduleCoords[2]] : group && name ? [group, name] : null;
      if (!coords) continue;
      const ref = line.match(/version\.ref\s*=\s*"([^"]+)"/)?.[1];
      const version = ref ? versions.get(ref) : line.match(/version\s*=\s*"([^"]+)"/)?.[1];
      if (!version || /^[[(]/.test(version)) continue;
      deps.push({ name: `${coords[0]}:${coords[1]}`, version, ecosystem: "Maven" });
    }
    return deps;
  },
};
