import { describe, expect, it } from "vitest";
import { checkSyntax } from "./syntax-check";

describe("checkSyntax", () => {
  it("passes valid TypeScript and fails a regression", async () => {
    expect((await checkSyntax("a.ts", "const a = 1;", "const a: number = 2;")).status).toBe("passed");
    const broken = await checkSyntax("a.ts", "const a = 1;", "const a = (1;");
    expect(broken.status).toBe("failed");
    expect(broken.detail).toMatch(/line 1/);
  });

  it("does not blame the fix when the original was already unparseable", async () => {
    expect((await checkSyntax("a.json", "{ // jsonc\n}", "{ // jsonc 2\n}")).status).toBe("skipped");
  });

  it("checks JSON and skips unknown file types", async () => {
    expect((await checkSyntax("p.json", '{"a":1}', '{"a":2}')).status).toBe("passed");
    expect((await checkSyntax("p.json", '{"a":1}', '{"a":2,}')).status).toBe("failed");
    expect((await checkSyntax("Dockerfile", "FROM a", "FROM b")).status).toBe("skipped");
  });
});
