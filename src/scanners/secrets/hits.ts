import { SeverityLevel } from "../types";

export interface SecretLineHit {
  ruleId: string;
  title: string;
  description: string;
  severity: SeverityLevel;
  startLine: number;
  endLine: number;
  snippet: string;
  confidence: number;
  masked: boolean;
}
