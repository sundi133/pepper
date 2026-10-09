/**
 * Language-aware review knowledge for the AI scanners.
 *
 * The guides in rules/review-knowledge/ (distilled from the MIT-licensed
 * awesome-skills/code-review-skill, see NOTICE.md there) tell the model which
 * sources, sinks, guards and logic flaws matter for the language it is
 * reading. They are knowledge for the model, never matched against code.
 */
import * as fs from "fs";
import * as path from "path";
import { FILE_EXTENSIONS } from "@/lib/constants";
import { logger } from "@/lib/logger";

/** FILE_EXTENSIONS language → guide file (without .md). */
const LANGUAGE_GUIDE: Record<string, string> = {
  javascript: "typescript",
  typescript: "typescript",
  template: "typescript",
  python: "python",
  go: "go",
  java: "java",
  kotlin: "java",
  scala: "java",
  php: "php",
  ruby: "ruby",
  csharp: "csharp",
  vbnet: "csharp",
  rust: "rust",
  c: "c",
  cpp: "c",
  "objective-c": "c",
  "objective-c++": "c",
  swift: "swift",
};

function knowledgeDir(): string {
  return (
    process.env.REVIEW_KNOWLEDGE_DIR?.trim() ||
    path.join(process.cwd(), "rules", "review-knowledge")
  );
}

const cache = new Map<string, string>();

function readGuide(name: string): string {
  const hit = cache.get(name);
  if (hit !== undefined) return hit;
  let text = "";
  try {
    text = fs.readFileSync(path.join(knowledgeDir(), `${name}.md`), "utf-8").trim();
  } catch (err) {
    logger.warn({ err, guide: name }, "Review knowledge guide not found; AI review continues without it");
  }
  cache.set(name, text);
  return text;
}

/** Guide name for a file, or undefined when no language guide applies. */
export function guideForFile(filePath: string): string | undefined {
  const lang = FILE_EXTENSIONS[path.extname(filePath).toLowerCase()];
  return lang ? LANGUAGE_GUIDE[lang] : undefined;
}

/**
 * The review knowledge block for the given files: the universal checklist plus
 * one guide per distinct language among them.
 */
export function reviewKnowledgeFor(filePaths: Array<string | undefined>): string {
  const guides = new Set<string>();
  for (const fp of filePaths) {
    const g = fp ? guideForFile(fp) : undefined;
    if (g) guides.add(g);
  }
  const parts = [readGuide("universal"), ...[...guides].map(readGuide)].filter(Boolean);
  if (parts.length === 0) return "";
  return `--- REVIEW KNOWLEDGE (apply to the code below; guidance, not findings) ---\n${parts.join("\n\n")}\n`;
}

/** Test hook: forget cached guides. */
export function resetReviewKnowledgeCache(): void {
  cache.clear();
}
