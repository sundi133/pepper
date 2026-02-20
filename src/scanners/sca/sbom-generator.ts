import { Dependency } from "../types";

interface CycloneDxComponent {
  type: string;
  name: string;
  version: string;
  purl: string;
  "bom-ref": string;
  scope?: string;
}

interface CycloneDxSbom {
  bomFormat: string;
  specVersion: string;
  serialNumber: string;
  version: number;
  metadata: {
    timestamp: string;
    tools: Array<{ vendor: string; name: string; version: string }>;
    component?: { type: string; name: string; version?: string };
  };
  components: CycloneDxComponent[];
}

export function generateSbom(
  dependencies: Dependency[],
  projectName = "unknown"
): CycloneDxSbom {
  const components: CycloneDxComponent[] = dependencies.map((dep, i) => ({
    type: "library",
    name: dep.name,
    version: dep.version,
    purl: buildPurl(dep),
    "bom-ref": `ref-${i}`,
    ...(dep.isDev ? { scope: "optional" } : {}),
  }));

  return {
    bomFormat: "CycloneDX",
    specVersion: "1.5",
    serialNumber: `urn:uuid:${crypto.randomUUID()}`,
    version: 1,
    metadata: {
      timestamp: new Date().toISOString(),
      tools: [
        {
          vendor: "Pepper",
          name: "pepper-sca",
          version: "1.0.0",
        },
      ],
      component: {
        type: "application",
        name: projectName,
      },
    },
    components,
  };
}

function buildPurl(dep: Dependency): string {
  const ecosystemMap: Record<string, string> = {
    npm: "npm",
    PyPI: "pypi",
    Go: "golang",
    Maven: "maven",
    "crates.io": "cargo",
    RubyGems: "gem",
    Packagist: "composer",
    NuGet: "nuget",
  };

  const type = ecosystemMap[dep.ecosystem] || dep.ecosystem.toLowerCase();

  if (dep.ecosystem === "Maven") {
    const [group, artifact] = dep.name.split(":");
    return `pkg:${type}/${group}/${artifact}@${dep.version}`;
  }

  return `pkg:${type}/${dep.name}@${dep.version}`;
}
