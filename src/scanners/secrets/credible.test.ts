import { describe, expect, it } from "vitest";
import {
  PATTERN_DETECTORS,
  isCredibleSecretMatch,
  isInlineTestCode,
  isJwt,
  isObviousNonSecret,
  isPrivateKeyBlock,
  isRealDatabaseUrl,
  looksLikeGeneratedSecret,
} from "./patterns";

/** What the scanner reports for one line: [credentialType, match] pairs. */
function reported(line: string, filePath = "src/config.ts"): string[] {
  const out: string[] = [];
  for (const [type, d] of Object.entries(PATTERN_DETECTORS)) {
    if (type === "PRIVATE_KEY") continue;
    for (const p of d.patterns) {
      for (const m of line.matchAll(new RegExp(p.source, p.flags))) {
        if (isCredibleSecretMatch(type, m[0], line, filePath)) out.push(type);
      }
    }
  }
  return out;
}

// Assembled at run time so this file holds no literal that looks like a live credential.
const j = (...parts: string[]) => parts.join("");

describe("database URLs", () => {
  it("ignores format strings, variables, local databases and stand-in passwords", () => {
    for (const line of [
      'let url = format!("postgres://{}:{}@{}:{}/{}", user, pass, host, port, db);',
      'DATABASE_URL="postgres://${DB_USER}:${DB_PASS}@${DB_HOST}/app"',
      "DATABASE_URL=postgres://$DB_USER:$DB_PASS@db.internal.corp/app",
      "DATABASE_URL=postgres://db_user:db_pass@localhost:5432/hyperswitch_db",
      "url: postgres://postgres:postgres@localhost/app",
      "url: postgresql://app:s3cr3tPw9@127.0.0.1:5432/app",
      "url: mysql://root:root@db:3306/app",
      "url: postgres://postgres:postgres@postgres:5432/app",
      "url: mongodb://<user>:<password>@cluster0.mongodb.net/app",
      "# Example: postgres://admin:Kx82hsQ1@db.prod.corp.net:5432/app",
      "url: postgres://user:password@db.prod.corp.net/app",
      "url: postgres://user:changeme@db.prod.corp.net/app",
    ]) {
      expect(reported(line), line).toEqual([]);
    }
  });

  it("still reports credentials for a reachable database", () => {
    for (const line of [
      "DATABASE_URL=postgres://app_rw:Kx82hsQ1zLp0@db.prod.corp.net:5432/app",
      'const url = "mongodb+srv://svc:9fQ2xLm7Rt@cluster0.ab1cd.mongodb.net/app";',
      "url: mysql://admin:admin@10.20.30.40:3306/app", // weak password on a real host
      "url: postgres://billing:Zt7wq91Lk@pg-primary:5432/billing", // real-looking password, service name
    ]) {
      expect(reported(line), line).toEqual(["DATABASE_URL"]);
    }
    expect(isRealDatabaseUrl("postgres://a:b@")).toBe(false);
  });
});

describe("generic api_key / secret assignments", () => {
  it("ignores descriptive text and names standing in for a value", () => {
    for (const line of [
      'api_key: "MyMerchantName-ApiKeyValue"',
      'api_key = "PowerTranz-PowerTranzPassword"',
      'api_key: "invalid-api-key-for-negative-case"',
      'secret_key = "paypal_secret_key_goes_here"',
      'client_secret: "paypal_client_secret_value"',
      'client_secret: "pay_nonexistent12345_secret_xyz"',
      'api_key = "{{ vault.payments.api_key }}"',
      'secret_key = "<your-secret-key-goes-here>"',
    ]) {
      expect(reported(line), line).toEqual([]);
    }
  });

  it("still reports generated-looking values", () => {
    expect(reported('api_key = "abcdefghij1234567890XXXXX"')).toEqual(["API_KEY"]);
    expect(reported('secret_key = "zyxwvutsrq9876543210YYYYY"')).toEqual(["SECRET_KEY"]);
    expect(looksLikeGeneratedSecret("9f8a7b6c5d4e3f2a1b0c9d8e7f6a5b4c")).toBe(true);
    expect(looksLikeGeneratedSecret("OnlyLettersNoDigitsHere")).toBe(false);
  });
});

describe("secret-named settings holding key material (GENERIC_SECRET)", () => {
  const hex64 = "73ad7bbbbc640c845a150f67d058b279849370cd2c1f3c67c4dd6c869213e13a";

  it("reports hardcoded keys in configuration and source", () => {
    expect(reported(`master_enc_key = "${hex64}"`, "config/development.toml")).toEqual(["GENERIC_SECRET"]);
    expect(reported(`const JWT_SECRET = "${hex64}";`, "src/auth.ts")).toEqual(["GENERIC_SECRET"]);
    expect(reported(`"db_password": "Zk9Qw3Lm8Rt2Xv7Bn4Hs6Jd1Fg5Yc0Pa"`, "settings.py")).toEqual(["GENERIC_SECRET"]);
  });

  it("is reported once when a specific detector matches the same setting", () => {
    // api_key / secret_key have their own detectors; the scanner drops the overlapping generic match.
    expect(reported(`secret_key = "${hex64}"`).sort()).toEqual(["GENERIC_SECRET", "SECRET_KEY"]);
  });

  it("ignores identifiers, short values, repeated units and names that are not secrets", () => {
    for (const line of [
      'psp_token: "0f03fd12-a1b2-4c3d-8e9f-0123456789ab"', // UUID
      '"token": "pm_0199ab3c45d67890123e4f5678a90123"', // prefixed id
      'hash_key = "0123456789abcdef0123456789abcdef"', // repeated unit
      'password = "Hunter2Hunter2"', // short: left to the AI pass
      `public_key = "${hex64}"`,
      `kms_key_id = "${hex64}"`,
      `cache_key = "${hex64}"`,
      'lock_key = "PRODUCER_LOCKING_KEY_FOR_SCHEDULER_V2"',
    ]) {
      expect(reported(line, "config/app.toml"), line).toEqual([]);
    }
  });

  it("is not applied to tests, examples and API documentation", () => {
    for (const f of [
      "cypress-tests/cypress/e2e/configs/Payout/Truelayer.js",
      "api-reference/v2/openapi_spec_v2.json",
      "config/config.example.toml",
      "src/auth.test.ts",
      "postman/collection-json/stripe.postman_collection.json",
    ]) {
      expect(reported(`master_enc_key = "${hex64}"`, f), f).toEqual([]);
    }
  });
});

describe("provider tokens", () => {
  it("still reports well-known token formats", () => {
    expect(reported(`aws = "${j("AKIA", "IOSFODNN7ABCDEFG")}"`)).toEqual(["AWS_ACCESS_KEY"]);
    expect(reported(`t = "${j("ghp", "_", "a1B2c3D4e5F6g7H8i9J0k1L2m3N4o5P6q7R8")}"`)).toEqual(["GITHUB_TOKEN"]);
    expect(reported(`k = "${j("sk", "_live_", "4eC39HqLyjWDarjtT1zdp7dc")}"`)).toEqual(["STRIPE_KEY"]);
    expect(reported(`k = "${j("rk", "_live_", "4eC39HqLyjWDarjtT1zdp7dc")}"`)).toEqual(["STRIPE_KEY"]);
  });

  it("reports the provider formats added for coverage", () => {
    expect(reported(`aws_secret_access_key = ${j("wJalrXUtnFEMI", "K7MDENGbPxRfiCYzT9qLm3Vn8sA")}`)).toEqual(["AWS_SECRET_ACCESS_KEY"]);
    expect(reported(`t = "${j("github", "_pat_", "11ABCDEFG0", "a1B2c3D4e5F6g7H8i9J0k1L2m3N4o5P6q7R8s9T0u1V2w3X4y5Z6a7B8c9D0e1F2g3H4i5J6")}"`)).toEqual(["GITHUB_TOKEN"]);
    expect(reported(`url = "${j("https://hooks.slack", ".com/services/", "T01ABCDEF/B01ABCDEF/", "a1B2c3D4e5F6g7H8i9J0k1L2")}"`)).toEqual(["SLACK_WEBHOOK"]);
    expect(reported(`conn = "DefaultEndpointsProtocol=https;AccountName=acct;${j("Account", "Key=")}${"Ab3dE9f".repeat(12)}Zz=="`)).toEqual(["AZURE_STORAGE_KEY"]);
    expect(reported(`k = "${j("sk-", "ant-", "api03-")}${"a1B2c3D4".repeat(6)}"`)).toContain("ANTHROPIC_API_KEY");
  });

  it("does not take a bare 40-character string for an AWS secret", () => {
    expect(reported('"integrity": "rVksvsnNCdJohGc6xgPwyN8eheCxsiLM8mxuEtmO"')).toEqual([]);
    expect(reported('"_postman_id": "9ab8f157-6b4b-430a-9ca8-34931682f988"')).toEqual([]);
  });

  it("does not report a Stripe publishable key, which is public by design", () => {
    expect(reported(`k = "${j("pk", "_live_", "4eC39HqLyjWDarjtT1zdp7dc")}"`)).toEqual([]);
  });

  it("reports a Google API key, except in the client config files that must carry one", () => {
    const line = `"current_key": "${j("AIza", "SyA1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q")}"`;
    expect(reported(line, "src/maps.ts")).toContain("GOOGLE_API_KEY");
    expect(reported(line, "android/app/google-services.json")).toEqual([]);
    expect(reported(line, "ios/App/GoogleService-Info.plist")).toEqual([]);
  });

  it("only accepts a JWT whose header is a JOSE header", () => {
    const b64 = (o: unknown) => Buffer.from(JSON.stringify(o)).toString("base64url");
    const real = `${b64({ alg: "HS256", typ: "JWT" })}.${b64({ sub: "1234567890" })}.c2lnbmF0dXJlLXNpZ25hdHVyZQ`;
    expect(isJwt(real)).toBe(true);
    expect(reported(`const t = "${real}";`)).toEqual(["JWT_TOKEN"]);
    expect(isJwt(`eyJub3RfYV9oZWFkZXI.${b64({ sub: "x" })}.c2lnbmF0dXJl`)).toBe(false);
  });
});

describe("private keys", () => {
  const body = "MIIEowIBAAKCAQEA1234567890abcdefghijklmnopqrstMIIEowIBAAKCAQEA1234567890";
  const at = (content: string) => content.indexOf("-----BEGIN");

  it("needs key material, not just a header", () => {
    const pem = `-----BEGIN RSA PRIVATE KEY-----\n${body}\n-----END RSA PRIVATE KEY-----`;
    expect(isPrivateKeyBlock(pem, at(pem))).toBe(true);
    const pkcs8 = `-----BEGIN PRIVATE KEY-----\n${body}\n-----END PRIVATE KEY-----`;
    expect(isPrivateKeyBlock(pkcs8, at(pkcs8))).toBe(true);
    const literal = `let k = "-----BEGIN RSA PRIVATE KEY-----\\n${body}\\n-----END RSA PRIVATE KEY-----";`;
    expect(isPrivateKeyBlock(literal, at(literal))).toBe(true);
  });

  it("rejects templates, truncated examples and bare headers", () => {
    for (const c of [
      'format!("-----BEGIN RSA PRIVATE KEY-----\\n{formatted_key}\\n-----END RSA PRIVATE KEY-----")',
      "-----BEGIN RSA PRIVATE KEY-----\n...\n-----END RSA PRIVATE KEY-----",
      "-----BEGIN PRIVATE KEY-----\n${PRIVATE_KEY}\n-----END PRIVATE KEY-----",
      'if key.starts_with("-----BEGIN RSA PRIVATE KEY-----") {',
    ]) {
      expect(isPrivateKeyBlock(c, at(c)), c).toBe(false);
    }
  });

  it("the PKCS#8 header is matched by the detector", () => {
    const [p] = PATTERN_DETECTORS.PRIVATE_KEY.patterns;
    expect(new RegExp(p.source, p.flags).test("-----BEGIN PRIVATE KEY-----")).toBe(true);
    expect(new RegExp(p.source, p.flags).test("-----BEGIN RSA PRIVATE KEY-----")).toBe(true);
    expect(new RegExp(p.source, p.flags).test("-----BEGIN PUBLIC KEY-----")).toBe(false);
  });

  it("is skipped when the line marks it as an example", () => {
    const line = '"example": "-----BEGIN RSA PRIVATE KEY-----\\nMIIE...\\n-----END RSA PRIVATE KEY-----"';
    expect(isCredibleSecretMatch("PRIVATE_KEY", "-----BEGIN RSA PRIVATE KEY-----", line)).toBe(false);
  });
});

describe("isInlineTestCode", () => {
  it("recognises a Rust #[cfg(test)] module", () => {
    const src = `fn real() {}\n#[cfg(test)]\nmod tests {\n  const KEY: &str = "x";\n}`;
    expect(isInlineTestCode("src/lib.rs", src, src.indexOf("KEY"))).toBe(true);
    expect(isInlineTestCode("src/lib.rs", src, src.indexOf("real"))).toBe(false);
    expect(isInlineTestCode("src/lib.ts", src, src.indexOf("KEY"))).toBe(false);
  });
});

describe("isObviousNonSecret (guard on the AI secrets pass)", () => {
  it("rejects references, templates, stand-ins and local connection strings", () => {
    for (const v of [
      "${DB_PASSWORD}",
      "$API_KEY",
      "{{ secrets.api_key }}",
      "{}",
      "<your-api-key>",
      "process.env.STRIPE_KEY",
      "os.environ['TOKEN']",
      "changeme",
      "your_api_key_here",
      "xxxxxxxxxxxxxxxx",
      "sk-fake-key-for-docs",
      "postgres://db_user:db_pass@localhost:5432/app",
    ]) {
      expect(isObviousNonSecret(v), v).toBe(true);
    }
  });

  it("keeps anything that could be real, including odd-looking passwords", () => {
    for (const v of [
      "Kx82hsQ1zLp0",
      "p@ss{w0rd}$9",
      "Contest2024!",
      "9f8a7b6c5d4e3f2a1b0c9d8e7f6a5b4c",
      "postgres://app_rw:Kx82hsQ1zLp0@db.prod.corp.net:5432/app",
      "",
    ]) {
      expect(isObviousNonSecret(v), v).toBe(false);
    }
  });
});
