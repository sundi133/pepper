/** Request validation shared by the report template API routes. */
import { z } from "zod";
import { MAX_INSTRUCTIONS_CHARS, MAX_TEMPLATE_CHARS, TEMPLATE_FORMATS } from "./template";

export const templateSchema = z.object({
  name: z.string().trim().min(1).max(120),
  description: z.string().max(1000).nullish(),
  format: z.enum(TEMPLATE_FORMATS).default("markdown"),
  body: z.string().min(1).max(MAX_TEMPLATE_CHARS),
  instructions: z.string().max(MAX_INSTRUCTIONS_CHARS).nullish(),
  sourceFileName: z.string().max(255).nullish(),
});

/** Prisma unique-constraint violation (duplicate template name in the org). */
export function isDuplicateName(e: unknown): boolean {
  return (e as { code?: string })?.code === "P2002";
}

/** PATCH body: every field optional, no defaults (a missing field is unchanged). */
export const templateUpdateSchema = z.object({
  name: z.string().trim().min(1).max(120).optional(),
  description: z.string().max(1000).nullish(),
  format: z.enum(TEMPLATE_FORMATS).optional(),
  body: z.string().min(1).max(MAX_TEMPLATE_CHARS).optional(),
  instructions: z.string().max(MAX_INSTRUCTIONS_CHARS).nullish(),
  sourceFileName: z.string().max(255).nullish(),
});
