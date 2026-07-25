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

/**
 * Package URL for a dependency. Exported so VEX documents identify components
 * with exactly the same identifiers as the SBOM — a VEX statement is only
 * useful if its subcomponent reference matches the SBOM it accompanies.
 */
export function purlFor(dep: Dependency): string {
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

/** deps.dev marker for a license string it could not map to SPDX. */
const NON_STANDARD = "non-standard";

/** True when the string is a compound SPDX expression rather than a bare ID. */
function isSpdxExpression(license: string): boolean {
  return /\s(AND|OR|WITH)\s/i.test(license) || license.includes("(");
}

/**
 * CycloneDX `licenses` entries. The spec requires a choice between a license
 * object (single ID/name) and an `expression` string for compound expressions,
 * so unmappable values are emitted as a free-text `name` rather than a bogus ID.
 */
function cycloneDxLicenses(
  licenses: string[] | undefined,
): Array<Record<string, unknown>> | undefined {
  const present = (licenses || []).filter((l) => l && l.trim());
  if (present.length === 0) return undefined;

  return present.map((license) => {
    const value = license.trim();
    if (isSpdxExpression(value)) return { expression: value };
    if (value.toLowerCase() === NON_STANDARD) {
      return { license: { name: value } };
    }
    return { license: { id: value } };
  });
}

/** CycloneDX 1.5 JSON. https://cyclonedx.org/specification/overview/ */
export function generateCycloneDx(
  dependencies: Dependency[],
  meta: SbomMetadata,
): string {
  const generatedAt = meta.generatedAt || new Date().toISOString();
  const components = dependencies.map((dep) => {
    const purl = purlFor(dep);
    const licenses = cycloneDxLicenses(dep.licenses);
    return {
      "bom-ref": purl,
      type: "library",
      name: dep.name,
      version: dep.version,
      purl,
      scope: dep.isDev ? "optional" : "required",
      ...(licenses ? { licenses } : {}),
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

/**
 * SPDX `licenseDeclared`. Multiple declared licenses are joined with OR, which
 * is how registries express dual licensing. Unmappable values become
 * NOASSERTION rather than an invalid license identifier.
 */
function spdxLicenseDeclared(licenses: string[] | undefined): string {
  const present = (licenses || [])
    .map((l) => l.trim())
    .filter((l) => l && l.toLowerCase() !== NON_STANDARD);
  if (present.length === 0) return "NOASSERTION";
  if (present.length === 1) return present[0];
  return present.map((l) => (isSpdxExpression(l) ? `(${l})` : l)).join(" OR ");
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
      // `licenseConcluded` stays NOASSERTION: we report what the registry
      // declares, we do not perform our own license audit of the source.
      licenseConcluded: "NOASSERTION",
      licenseDeclared: spdxLicenseDeclared(dep.licenses),
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
