import { describe, expect, it } from "vitest";
import { createRedactionSession, llmMaskingEnabled, SECRET_TOKEN_RE } from "./llm-redaction";

const AWS = "AKIAQ3ZRT5WJ4N6P2LMB";
const GH = "ghp_" + "a1B2c3D4e5F6g7H8i9J0k1L2m3N4o5P6q7R8";

function redact(text: string) {
  const s = createRedactionSession();
  return { out: s.redact(text), s };
}

describe("llm redaction", () => {
  it("masks shaped credentials, keeping only their public prefix", () => {
    const { out } = redact(`const k = "${AWS}";\nconst t = '${GH}';`);
    expect(out).not.toContain(AWS);
    expect(out).not.toContain(GH);
    expect(out).toMatch(/\[\[SECRET_1 type=aws_access_key prefix=AKIA len=20 entropy=\d\.\d\]\]/);
    expect(out).toMatch(/\[\[SECRET_2 type=github_token prefix=ghp_ len=40/);
  });

  it("masks secret-named assignments in code and config, but not references or placeholders", () => {
    const text = [
      `db.password = "Tr0ub4dor&3xK";`,
      `"client_secret": "9f8e7d6c5b4a3f2e1d0c",`,
      `DB_PASSWORD=s3cr3t-Pa55w0rd!`,
      `api_key: Zx81kQ02mLp94Rt5`,
      `password = os.environ["DB_PASSWORD"]`,
      `token = getToken()`,
      `secret_key = settings.SECRET_KEY`,
      `password: "changeme"`,
      `API_KEY=\${API_KEY}`,
      `const passwordLabel = "Enter your password";`,
      `token = user.token`,
      `apiKey: config.apiKey`,
      `password = myVar2`,
      `if (password == "") return;`,
    ].join("\n");
    const { out, s } = redact(text);
    const lines = out.split("\n");
    for (const i of [0, 1, 2, 3]) expect(lines[i], lines[i]).toMatch(/\[\[SECRET_\d+ type=named_secret len=\d+/);
    for (const i of [4, 5, 6, 7, 8, 9, 10, 11, 12, 13]) expect(lines[i], lines[i]).toBe(text.split("\n")[i]);
    expect(s.count).toBe(4);
    // named secrets never reveal characters
    expect(out).not.toMatch(/type=named_secret prefix=/);
  });

  it("masks only the password in URLs and connection strings", () => {
    const { out } = redact(
      `DATABASE_URL=postgres://app:Hunter2Hunter2@db.internal:5432/app\nServer=sql01;Database=pay;User Id=svc;Password=Pa$$w0rd99;`,
    );
    expect(out).toContain("postgres://app:[[SECRET_1 type=url_password");
    expect(out).toContain("@db.internal:5432/app");
    expect(out).toContain("User Id=svc;Password=[[SECRET_2 type=connection_string_password");
    expect(out).not.toMatch(/Hunter2|Pa\$\$w0rd99/);
  });

  it("keeps line numbers when masking a private key block", () => {
    const pem = "-----BEGIN RSA PRIVATE KEY-----\nMIIEow\nAAAA\n-----END RSA PRIVATE KEY-----";
    const text = `line1\n${pem}\nafter`;
    const { out } = redact(text);
    expect(out.split("\n")).toHaveLength(text.split("\n").length);
    expect(out.split("\n").at(-1)).toBe("after");
    expect(out).not.toContain("MIIEow");
  });

  it("gives the same value the same token and restores exactly", () => {
    const s = createRedactionSession();
    const a = s.redact(`key1 = "${AWS}"`);
    const b = s.redact(`again ${AWS}`);
    expect(a.match(SECRET_TOKEN_RE)![0]).toBe(b.match(SECRET_TOKEN_RE)![0]);
    // A model may echo the token with or without its metadata.
    expect(s.restore(`replace [[SECRET_1]] and ${b.match(SECRET_TOKEN_RE)![0]}`)).toBe(`replace ${AWS} and ${AWS}`);
    expect(s.restore("[[SECRET_99]]")).toBe("[[SECRET_99]]");
  });

  it("masks code inside JSON payloads and restores the unescaped value", () => {
    const file = `const db = {\n  password: "Tr0ub4dor&3xK",\n  key: "${AWS}",\n};\n`;
    const payload = JSON.stringify({ finding: { title: "Hardcoded password" }, originalFile: file });
    const s = createRedactionSession();
    const out = s.redact(payload);
    expect(out).not.toContain("Tr0ub4dor");
    expect(out).not.toContain(AWS);
    const parsed = JSON.parse(out) as { originalFile: string; finding: { title: string } };
    expect(parsed.finding.title).toBe("Hardcoded password");
    expect(parsed.originalFile.split("\n")).toHaveLength(file.split("\n").length);
    expect(s.restore(parsed.originalFile)).toBe(file);
    // Pretty-printed payloads keep their indentation; untouched JSON is returned as is.
    expect(s.redact(JSON.stringify({ a: `x = "${AWS}"` }, null, 2))).toContain('\n  "a": ');
    const clean = JSON.stringify({ code: "return a + b;" });
    expect(s.redact(clean)).toBe(clean);
  });

  it("masks top-level secret fields in JSON", () => {
    const { out } = redact(`{"client_secret": "9f8e7d6c5b4a3f2e1d0c", "name": "app"}`);
    expect(out).not.toContain("9f8e7d6c5b4a3f2e1d0c");
    expect(out).toContain(`"name": "app"`);
  });

  it("leaves ordinary code alone", () => {
    const code = `function login(user, password) {\n  if (!password) throw new Error("password required");\n  return hash(password, salt);\n}`;
    expect(redact(code).out).toBe(code);
  });

  it("is on unless explicitly disabled", () => {
    expect(llmMaskingEnabled({})).toBe(true);
    expect(llmMaskingEnabled({ LLM_MASK_SECRETS: "false" })).toBe(false);
    expect(llmMaskingEnabled({ LLM_MASK_SECRETS: "true" })).toBe(true);
  });
});
