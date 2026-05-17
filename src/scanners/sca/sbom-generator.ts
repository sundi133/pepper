import { createHash, randomUUID } from "crypto";
import type { Dependency } from "../types";

export interface SbomMetadata {
  projectName: string;
  projectVersion?: string;
  scanId: string;
  commitSha?: string;
  branch?: string;
  /** ISO timestamp; defaults to now */
  generatedAt?: string;
}

const TOOL_VENDOR = "Pepper";
const TOOL_NAME = "pepper-sca";
const TOOL_VERSION = "1.0.0";

function purlFor(dep: Dependency): string {
  const eco = dep.ecosystem.toLowerCase();
  const ecoMap: Record<string, string> = {
    npm: "npm",
    pypi: "pypi",
    pip: "pypi",
    maven: "maven",
    gradle: "maven",
    go: "golang",
    cargo: "cargo",
    rubygems: "gem",
    gem: "gem",
    composer: "composer",
    packagist: "composer",
    nuget: "nuget",
    pub: "pub",
    hex: "hex",
    swift: "swift",
  };
  const purlType = ecoMap[eco] || eco;
  const name = encodeURIComponent(dep.name);
  if (purlType === "maven" && dep.name.includes(":")) {
    const [group, artifact] = dep.name.split(":");
    return `pkg:maven/${encodeURIComponent(group)}/${encodeURIComponent(artifact)}@${encodeURIComponent(dep.version)}`;
  }
  return `pkg:${purlType}/${name}@${encodeURIComponent(dep.version)}`;
}

/** CycloneDX 1.5 JSON. https://cyclonedx.org/specification/overview/ */
export function generateCycloneDx(
  dependencies: Dependency[],
  meta: SbomMetadata,
): string {
  const generatedAt = meta.generatedAt || new Date().toISOString();
  const components = dependencies.map((dep) => {
    const purl = purlFor(dep);
    return {
      "bom-ref": purl,
      type: "library",
      name: dep.name,
      version: dep.version,
      purl,
      scope: dep.isDev ? "optional" : "required",
      properties: [
        { name: "pepper:ecosystem", value: dep.ecosystem },
        ...(dep.lockfileVersion
          ? [{ name: "pepper:lockfileVersion", value: dep.lockfileVersion }]
          : []),
      ],
    };
  });

  const bom = {
    bomFormat: "CycloneDX",
    specVersion: "1.5",
    serialNumber: `urn:uuid:${randomUUID()}`,
    version: 1,
    metadata: {
      timestamp: generatedAt,
      tools: [{ vendor: TOOL_VENDOR, name: TOOL_NAME, version: TOOL_VERSION }],
      component: {
        "bom-ref": `pkg:generic/${encodeURIComponent(meta.projectName)}`,
        type: "application",
        name: meta.projectName,
        version: meta.projectVersion || meta.commitSha || "0.0.0",
        properties: [
          ...(meta.commitSha
            ? [{ name: "pepper:commitSha", value: meta.commitSha }]
            : []),
          ...(meta.branch
            ? [{ name: "pepper:branch", value: meta.branch }]
            : []),
          { name: "pepper:scanId", value: meta.scanId },
        ],
      },
    },
    components,
  };

  return JSON.stringify(bom, null, 2);
}

/** SPDX 2.3 JSON. https://spdx.github.io/spdx-spec/v2.3/ */
export function generateSpdx(
  dependencies: Dependency[],
  meta: SbomMetadata,
): string {
  const generatedAt = meta.generatedAt || new Date().toISOString();
  const documentNamespace = `https://pepper.local/spdx/${meta.scanId}/${randomUUID()}`;

  interface SpdxPackage {
    SPDXID: string;
    name: string;
    versionInfo: string;
    downloadLocation: string;
    filesAnalyzed: boolean;
    licenseConcluded: string;
    licenseDeclared: string;
    copyrightText: string;
    externalRefs?: {
      referenceCategory: string;
      referenceType: string;
      referenceLocator: string;
    }[];
  }

  const rootRef = "SPDXRef-Package-Root";
  const packages: SpdxPackage[] = [
    {
      SPDXID: rootRef,
      name: meta.projectName,
      versionInfo: meta.projectVersion || meta.commitSha || "NOASSERTION",
      downloadLocation: "NOASSERTION",
      filesAnalyzed: false,
      licenseConcluded: "NOASSERTION",
      licenseDeclared: "NOASSERTION",
      copyrightText: "NOASSERTION",
    },
  ];

  const relationships = [
    {
      spdxElementId: "SPDXRef-DOCUMENT",
      relatedSpdxElement: rootRef,
      relationshipType: "DESCRIBES",
    },
  ];

  for (const dep of dependencies) {
    const purl = purlFor(dep);
    const safeName = `${dep.ecosystem}-${dep.name}-${dep.version}`.replace(
      /[^A-Za-z0-9.-]/g,
      "-",
    );
    const hash = createHash("sha1").update(purl).digest("hex").slice(0, 8);
    const spdxId = `SPDXRef-Pkg-${safeName}-${hash}`.slice(0, 200);
    packages.push({
      SPDXID: spdxId,
      name: dep.name,
      versionInfo: dep.version,
      downloadLocation: "NOASSERTION",
      filesAnalyzed: false,
      licenseConcluded: "NOASSERTION",
      licenseDeclared: "NOASSERTION",
      copyrightText: "NOASSERTION",
      externalRefs: [
        {
          referenceCategory: "PACKAGE-MANAGER",
          referenceType: "purl",
          referenceLocator: purl,
        },
      ],
    });
    relationships.push({
      spdxElementId: rootRef,
      relatedSpdxElement: spdxId,
      relationshipType: dep.isDev ? "DEV_DEPENDENCY_OF" : "DEPENDS_ON",
    });
  }

  const doc = {
    spdxVersion: "SPDX-2.3",
    dataLicense: "CC0-1.0",
    SPDXID: "SPDXRef-DOCUMENT",
    name: `${meta.projectName}-sbom`,
    documentNamespace,
    creationInfo: {
      created: generatedAt,
      creators: [
        `Tool: ${TOOL_NAME}-${TOOL_VERSION}`,
        `Organization: ${TOOL_VENDOR}`,
      ],
    },
    packages,
    relationships,
  };

  return JSON.stringify(doc, null, 2);
}
