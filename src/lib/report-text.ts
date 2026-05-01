/**
 * Turns stored report strings into readable text for customer-facing UIs.
 * If a field was mistakenly saved as JSON, parses it and flattens to lines.
 * Accepts non-strings (e.g. array/object from JSON columns) and coerces safely.
 */
export function normalizeCustomerFacingText(raw: unknown): string {
  if (raw == null) return "";
  if (typeof raw !== "string") {
    if (typeof raw === "number" || typeof raw === "boolean") {
      return String(raw);
    }
    if (typeof raw === "object") {
      return jsonValueToReadableLines(raw);
    }
    return String(raw);
  }
  const t = raw.trim();
  if (!t) return "";
  if (
    (t.startsWith("{") && t.endsWith("}")) ||
    (t.startsWith("[") && t.endsWith("]"))
  ) {
    try {
      const parsed = JSON.parse(t) as unknown;
      return jsonValueToReadableLines(parsed);
    } catch {
      return raw;
    }
  }
  return raw;
}

function jsonValueToReadableLines(v: unknown): string {
  if (v == null) return "";
  if (typeof v === "string") return v;
  if (typeof v === "number" || typeof v === "boolean") return String(v);
  if (Array.isArray(v)) {
    return v
      .map((x) => jsonValueToReadableLines(x))
      .filter(Boolean)
      .join("\n");
  }
  if (typeof v === "object") {
    const lines: string[] = [];
    for (const [k, val] of Object.entries(v as Record<string, unknown>)) {
      const inner = jsonValueToReadableLines(val);
      lines.push(inner.includes("\n") ? `${k}:\n${inner}` : `${k}: ${inner}`);
    }
    return lines.join("\n");
  }
  return String(v);
}

export function normalizeAttackPreconditionsValues<T extends Record<string, unknown>>(
  pre: T,
): T {
  const out = { ...pre } as Record<string, unknown>;
  for (const k of Object.keys(out)) {
    const v = out[k];
    if (typeof v === "string") {
      out[k] = normalizeCustomerFacingText(v);
    }
  }
  return out as T;
}
