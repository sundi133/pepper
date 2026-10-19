import { beforeEach, describe, expect, it, vi } from "vitest";
import { generateKeyPairSync, verify } from "crypto";
import {
  clearInstallationTokenCache,
  createAppJwt,
  getInstallationToken,
  githubAppConfig,
  githubAppInstallUrl,
  parsePrivateKey,
  userCanAccessInstallation,
  withGithubAppCredentials,
} from "./github-app";

const { privateKey, publicKey } = generateKeyPairSync("rsa", { modulusLength: 2048 });
const PEM = privateKey.export({ type: "pkcs1", format: "pem" }).toString();
const ENV = {
  GITHUB_APP_ID: "12345",
  GITHUB_APP_SLUG: "pepper-test",
  GITHUB_APP_PRIVATE_KEY: PEM,
  GITHUB_APP_CLIENT_ID: "Iv1.abc",
  GITHUB_APP_CLIENT_SECRET: "secret",
};

const json = (status: number, body: unknown) => ({ ok: status < 300, status, json: async () => body }) as unknown as Response;

describe("configuration", () => {
  it("is off unless every required setting is present", () => {
    expect(githubAppConfig({})).toBeNull();
    expect(githubAppConfig({ ...ENV, GITHUB_APP_CLIENT_SECRET: "" })).toBeNull();
    expect(githubAppConfig(ENV)).toMatchObject({ appId: "12345", slug: "pepper-test", webhookSecret: null });
  });

  it("accepts the key as PEM, PEM with literal \\n, or base64, and rejects garbage", () => {
    expect(parsePrivateKey(PEM).asymmetricKeyType).toBe("rsa");
    expect(parsePrivateKey(PEM.replace(/\n/g, "\\n")).asymmetricKeyType).toBe("rsa");
    expect(parsePrivateKey(Buffer.from(PEM).toString("base64")).asymmetricKeyType).toBe("rsa");
    expect(githubAppConfig({ ...ENV, GITHUB_APP_PRIVATE_KEY: "not a key" })).toBeNull();
  });
});

describe("App JWT", () => {
  it("is an RS256 JWT for the App, valid under ten minutes, verifiable with the public key", () => {
    const cfg = githubAppConfig(ENV)!;
    const jwt = createAppJwt(cfg, 1_000_000);
    const [h, p, sig] = jwt.split(".");
    expect(JSON.parse(Buffer.from(h, "base64url").toString())).toEqual({ alg: "RS256", typ: "JWT" });
    const claims = JSON.parse(Buffer.from(p, "base64url").toString());
    expect(claims).toEqual({ iat: 1_000_000 - 60, exp: 1_000_000 + 540, iss: "12345" });
    expect(claims.exp - claims.iat).toBeLessThanOrEqual(600);
    expect(verify("RSA-SHA256", Buffer.from(`${h}.${p}`), publicKey, Buffer.from(sig, "base64url"))).toBe(true);
  });
});

describe("installation tokens", () => {
  const cfg = githubAppConfig(ENV)!;
  beforeEach(() => clearInstallationTokenCache());

  it("mints once and reuses the token until five minutes before it expires", async () => {
    const now = Date.parse("2026-10-19T10:00:00Z");
    const f = vi.fn(async () => json(201, { token: "ghs_one", expires_at: "2026-10-19T11:00:00Z" }));
    expect(await getInstallationToken(cfg, 7, f as never, now)).toMatchObject({ ok: true, token: "ghs_one" });
    expect(await getInstallationToken(cfg, 7, f as never, now + 30 * 60_000)).toMatchObject({ ok: true, token: "ghs_one" });
    expect(f).toHaveBeenCalledTimes(1);
    const [url, init] = f.mock.calls[0] as unknown as [string, { method: string; headers: Record<string, string> }];
    expect(url).toBe("https://api.github.com/app/installations/7/access_tokens");
    expect(init.method).toBe("POST");
    expect(init.headers.Authorization).toMatch(/^Bearer ey/);
    f.mockResolvedValueOnce(json(201, { token: "ghs_two", expires_at: "2026-10-19T12:00:00Z" }));
    expect(await getInstallationToken(cfg, 7, f as never, now + 56 * 60_000)).toMatchObject({ ok: true, token: "ghs_two" });
  });

  it("reports removed and suspended installations", async () => {
    expect(await getInstallationToken(cfg, 8, (async () => json(404, { message: "Not Found" })) as never)).toEqual({ ok: false, reason: "removed", status: 404 });
    expect(await getInstallationToken(cfg, 9, (async () => json(403, { message: "This installation has been suspended" })) as never)).toEqual({ ok: false, reason: "suspended", status: 403 });
    expect(await getInstallationToken(cfg, 10, (async () => json(500, {})) as never)).toMatchObject({ ok: false, reason: "error" });
  });
});

describe("linking checks", () => {
  it("finds the installation among the user's, across pages, and refuses otherwise", async () => {
    const page1 = { installations: Array.from({ length: 100 }, (_, i) => ({ id: i + 1 })) };
    const f = vi.fn(async (url: string) => json(200, /[?&]page=1$/.test(url) ? page1 : { installations: [{ id: 555 }] }));
    expect(await userCanAccessInstallation("ghu_x", 555, f as never)).toBe(true);
    expect(await userCanAccessInstallation("ghu_x", 999, f as never)).toBe(false);
    expect(await userCanAccessInstallation("ghu_x", 1, (async () => json(401, {})) as never)).toBe(false);
  });

  it("builds the install link and App clone URLs", () => {
    expect(githubAppInstallUrl({ slug: "pepper-test" }, "a.b")).toBe("https://github.com/apps/pepper-test/installations/new?state=a.b");
    expect(withGithubAppCredentials("https://github.com/acme/api.git", "ghs_t")).toBe("https://x-access-token:ghs_t@github.com/acme/api.git");
    expect(withGithubAppCredentials("git@github.com:acme/api.git", "ghs_t")).toBe("git@github.com:acme/api.git");
  });
});
