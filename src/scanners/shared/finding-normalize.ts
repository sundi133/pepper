import type { RawFinding } from "../types";
import type { FindingMetadata } from "./finding-metadata";
import { mergeMetadata } from "./finding-metadata";

export interface StructuredFindingFields {
  whatIsWrong: string;
  where: string;
  whyExploitable: string;
  attackPath?: string;
  impact?: string;
  stepsToReproduce?: string[];
  fix: string;
  validation?: string;
}

/** Build developer-ready description from structured sections. */
export function buildStructuredDescription(
  fields: StructuredFindingFields,
): string {
  const parts: string[] = [
    `**What is wrong:** ${fields.whatIsWrong}`,
    `**Where:** ${fields.where}`,
    `**Why it is exploitable:** ${fields.whyExploitable}`,
  ];
  if (fields.attackPath) {
    parts.push(`**Attack path:** ${fields.attackPath}`);
  }
  if (fields.impact) {
    parts.push(`**Impact:** ${fields.impact}`);
  }
  if (fields.stepsToReproduce?.length) {
    parts.push(
      `**Steps to reproduce safely:**\n${fields.stepsToReproduce.map((s, i) => `${i + 1}. ${s}`).join("\n")}`,
    );
  }
  parts.push(`**Fix:** ${fields.fix}`);
  if (fields.validation) {
    parts.push(`**How to validate the fix:** ${fields.validation}`);
  }
  return parts.join("\n\n");
}

export function enrichFinding(
  finding: RawFinding,
  meta: Partial<FindingMetadata>,
  structured?: Partial<StructuredFindingFields>,
): RawFinding {
  const remediation =
    meta.remediation ||
    structured?.fix ||
    (finding.metadata?.remediation as string | undefined);

  const description =
    structured && Object.keys(structured).length > 0
      ? buildStructuredDescription({
          whatIsWrong: structured.whatIsWrong || finding.title,
          where:
            structured.where ||
            [finding.filePath, finding.startLine && `line ${finding.startLine}`]
              .filter(Boolean)
              .join(":") ||
            "See evidence",
          whyExploitable:
            structured.whyExploitable ||
            finding.description.split("\n")[0] ||
            finding.description,
          attackPath: structured.attackPath || meta.attackPath,
          impact: structured.impact || meta.impact,
          stepsToReproduce:
            structured.stepsToReproduce || meta.stepsToReproduce,
          fix: structured.fix || remediation || "Apply the recommended fix.",
          validation:
            structured.validation ||
            (meta.validationSteps as string[] | undefined)?.join("; "),
        })
      : finding.description;

  return {
    ...finding,
    description,
    metadata: mergeMetadata(finding.metadata, {
      ...meta,
      remediation: remediation || meta.remediation,
    }),
  };
}
