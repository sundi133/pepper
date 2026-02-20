import { PatternRule } from "../types";

// Import language-specific rules
import { javascriptRules } from "./rules/javascript";
import { pythonRules } from "./rules/python";
import { goRules } from "./rules/go";
import { javaRules } from "./rules/java";
import { genericRules } from "./rules/generic";

export const ALL_PATTERN_RULES: PatternRule[] = [
  ...javascriptRules,
  ...pythonRules,
  ...goRules,
  ...javaRules,
  ...genericRules,
];

export function getRulesForLanguage(language: string): PatternRule[] {
  return ALL_PATTERN_RULES.filter(
    (rule) => rule.languages.includes(language) || rule.languages.includes("*")
  );
}
