import { NextRequest, NextResponse } from "next/server";

interface VulnerabilityInfo {
  description: string;
  impact: string;
  remediation: string[];
}

// Research vulnerability details from online sources (NVD, npm, etc.)
async function researchVulnerability(
  packageName: string,
  cveId?: string,
  version?: string
): Promise<VulnerabilityInfo | null> {
  try {
    // Try to fetch from NVD API if CVE is provided
    if (cveId) {
      const nvdResponse = await fetch(
        `https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=${cveId}`,
        { signal: AbortSignal.timeout(5000) }
      );

      if (nvdResponse.ok) {
        const nvdData = await nvdResponse.json();
        const vulnerability = nvdData.vulnerabilities?.[0]?.cve;

        if (vulnerability) {
          const description =
            vulnerability.descriptions?.[0]?.value ||
            `Vulnerability ${cveId} in ${packageName}`;

          const impact = vulnerability.metrics?.cvssMetricV31?.[0]?.cvssData?.baseSeverity ||
            vulnerability.metrics?.cvssMetricV3?.[0]?.cvssData?.baseSeverity ||
            "Unknown severity";

          return {
            description,
            impact: `This vulnerability has a CVSS severity rating of ${impact}.`,
            remediation: [
              `Update ${packageName} to a patched version that addresses ${cveId}`,
              "Test thoroughly after updating to ensure compatibility",
              "Monitor security advisories for future updates",
            ],
          };
        }
      }
    }

    // Fallback: Try npm API for package information
    const npmResponse = await fetch(
      `https://registry.npmjs.org/${packageName}`,
      { signal: AbortSignal.timeout(5000) }
    );

    if (npmResponse.ok) {
      const npmData = await npmResponse.json();
      const packageInfo = npmData;

      return {
        description: packageInfo.description || `${packageName} is a vulnerable dependency`,
        impact:
          packageInfo.keywords?.includes("security") ||
          packageInfo.keywords?.includes("vulnerability")
            ? `This package has known security vulnerabilities that require immediate patching.`
            : `Update this dependency to the latest secure version.`,
        remediation: [
          `Run: npm update ${packageName}`,
          `Or upgrade to the latest version: npm install ${packageName}@latest`,
          "Run npm audit to identify other vulnerabilities",
          "Test your application after updating dependencies",
        ],
      };
    }

    return null;
  } catch (error) {
    console.error("Error researching vulnerability:", error);
    return null;
  }
}

export async function GET(request: NextRequest) {
  try {
    const searchParams = request.nextUrl.searchParams;
    const packageName = searchParams.get("package");
    const cveId = searchParams.get("cve");
    const version = searchParams.get("version");

    if (!packageName) {
      return NextResponse.json(
        { error: "Package name is required" },
        { status: 400 }
      );
    }

    const vulnData = await researchVulnerability(packageName, cveId || undefined, version || undefined);

    if (!vulnData) {
      return NextResponse.json(
        {
          description: `No specific vulnerability data found for ${packageName}`,
          impact: "Please check npm registry or security advisories for more information",
          remediation: [
            `Check npm audit: npm audit ${packageName}`,
            "Visit https://nvd.nist.gov for CVE information",
            "Check the package's GitHub security advisories",
          ],
        },
        { status: 200 }
      );
    }

    return NextResponse.json(vulnData);
  } catch (error) {
    console.error("Vulnerability research error:", error);
    return NextResponse.json(
      { error: "Failed to research vulnerability" },
      { status: 500 }
    );
  }
}
