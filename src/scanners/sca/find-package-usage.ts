import * as fs from "fs";
import * as path from "path";
import { SKIP_DIRECTORIES, FILE_EXTENSIONS } from "@/lib/constants";
import { logger } from "@/lib/logger";

/**
 * Find where a package is imported/required in source code
 * Returns array of file paths where the package is used
 */
export async function findPackageUsage(
  workDir: string,
  fileList: string[],
  packageName: string,
): Promise<string[]> {
  const usageLocations: Set<string> = new Set();

  // Escape special regex characters in package name
  const escapedName = packageName.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");

  // Create patterns for different import styles
  const patterns = [
    // CommonJS require: require('package-name')
    new RegExp(`require\\s*\\(\\s*['"](${escapedName})['"]\\s*\\)`, "g"),
    // CommonJS require: require('package-name/subpath')
    new RegExp(`require\\s*\\(\\s*['"](${escapedName}(?:/[^'"]*)?)['"]\\s*\\)`, "g"),
    // ES6 import: import from 'package-name'
    new RegExp(`import\\s+.*from\\s+['"](${escapedName})['"]`, "g"),
    // ES6 import: import from 'package-name/subpath'
    new RegExp(`import\\s+.*from\\s+['"](${escapedName}(?:/[^'"]*)?)['"]`, "g"),
    // Dynamic import: import('package-name')
    new RegExp(`import\\s*\\(\\s*['"](${escapedName})['"]\\s*\\)`, "g"),
    // Dynamic import with subpath: import('package-name/subpath')
    new RegExp(`import\\s*\\(\\s*['"](${escapedName}(?:/[^'"]*)?)['"]\\s*\\)`, "g"),
  ];

  const sourceExtensions = new Set([
    ".js",
    ".ts",
    ".tsx",
    ".jsx",
    ".py",
    ".go",
    ".java",
    ".rb",
    ".php",
    ".cs",
    ".rs",
    ".c",
    ".cpp",
    ".h",
    ".hpp",
    ".swift",
    ".kt",
    ".scala",
    ".sh",
    ".bash",
  ]);

  for (const filePath of fileList) {
    const ext = path.extname(filePath).toLowerCase();

    // Only check source files
    if (!sourceExtensions.has(ext)) continue;

    // Skip directories
    const parts = filePath.split(path.sep);
    if (parts.some((p) => SKIP_DIRECTORIES.has(p))) continue;

    const fullPath = path.join(workDir, filePath);

    try {
      const content = fs.readFileSync(fullPath, "utf-8");

      // Check if any pattern matches
      for (const pattern of patterns) {
        if (pattern.test(content)) {
          usageLocations.add(filePath);
          break; // Found in this file, move to next file
        }
      }
    } catch (err) {
      // Skip files that can't be read
      continue;
    }
  }

  return Array.from(usageLocations).sort();
}

/**
 * Find where a package is imported with line numbers
 */
export async function findPackageUsageWithLines(
  workDir: string,
  fileList: string[],
  packageName: string,
): Promise<Array<{ filePath: string; line: number; usage: string }>> {
  const usageDetails: Array<{ filePath: string; line: number; usage: string }> = [];

  const escapedName = packageName.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");

  const patterns = [
    new RegExp(`require\\s*\\(\\s*['"](${escapedName})['"](\\s*\\)|[,])`, "g"),
    new RegExp(`import\\s+.*from\\s+['"](${escapedName})['"]`, "g"),
    new RegExp(`import\\s*\\(\\s*['"](${escapedName})['"]\\s*\\)`, "g"),
  ];

  const sourceExtensions = new Set([
    ".js",
    ".ts",
    ".tsx",
    ".jsx",
    ".py",
    ".go",
    ".java",
    ".rb",
    ".php",
    ".cs",
    ".rs",
    ".c",
    ".cpp",
    ".h",
    ".hpp",
    ".swift",
    ".kt",
    ".scala",
    ".sh",
    ".bash",
  ]);

  for (const filePath of fileList) {
    const ext = path.extname(filePath).toLowerCase();

    if (!sourceExtensions.has(ext)) continue;

    const parts = filePath.split(path.sep);
    if (parts.some((p) => SKIP_DIRECTORIES.has(p))) continue;

    const fullPath = path.join(workDir, filePath);

    try {
      const content = fs.readFileSync(fullPath, "utf-8");
      const lines = content.split("\n");

      for (let lineNum = 0; lineNum < lines.length; lineNum++) {
        const line = lines[lineNum];

        for (const pattern of patterns) {
          if (pattern.test(line)) {
            const usage = line.trim();
            usageDetails.push({
              filePath,
              line: lineNum + 1,
              usage: usage.substring(0, 100), // Limit to 100 chars
            });
            pattern.lastIndex = 0; // Reset regex
            break;
          }
        }
      }
    } catch (err) {
      continue;
    }
  }

  return usageDetails;
}
