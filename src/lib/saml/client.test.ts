import { describe, expect, it } from "vitest";
import { extractSamlIdentity } from "./client";
import type { SamlRuntimeConfig } from "./config";

const baseCfg: SamlRuntimeConfig = {
  saml: {
    entryPoint: "https://idp.example/sso",
    issuer: "sp",
    callbackUrl: "https://app/acs",
    idpCert: "cert",
    wantAssertionsSigned: true,
    audience: "sp",
    identifierFormat: null,
  },
  emailAttr: "",
  nameAttr: "",
  groupAttr: "groups",
  roleMap: {},
  defaultRole: "VIEWER",
  defaultOrgSlug: "",
};

describe("extractSamlIdentity", () => {
  it("prefers configured attribute names", () => {
    const cfg = { ...baseCfg, emailAttr: "mailAddress", nameAttr: "fullName" };
    const id = extractSamlIdentity(
      { mailAddress: "Jo@Example.com", fullName: "Jo Diaz", groups: ["a"] },
      cfg,
    );
    expect(id).toEqual({ email: "jo@example.com", name: "Jo Diaz", groups: ["a"] });
  });

  it("falls back to common email/name keys", () => {
    const id = extractSamlIdentity(
      { email: "x@y.com", displayName: "X Y", groups: "eng" },
      baseCfg,
    );
    expect(id.email).toBe("x@y.com");
    expect(id.name).toBe("X Y");
    expect(id.groups).toEqual(["eng"]);
  });

  it("uses nameID as email of last resort", () => {
    const id = extractSamlIdentity({ nameID: "user@corp.com" }, baseCfg);
    expect(id.email).toBe("user@corp.com");
  });

  it("joins given + family name when no display name is present", () => {
    const id = extractSamlIdentity(
      { email: "a@b.com", givenName: "Ada", surname: "Byron" },
      baseCfg,
    );
    expect(id.name).toBe("Ada Byron");
  });

  it("returns empty email when nothing resolves (caller rejects)", () => {
    const id = extractSamlIdentity({ nameID: "not-an-email" }, baseCfg);
    expect(id.email).toBe("");
  });

  it("reads groups from the configured group attribute", () => {
    const cfg = { ...baseCfg, groupAttr: "memberOf" };
    const id = extractSamlIdentity(
      { email: "a@b.com", memberOf: ["admins", "eng"] },
      cfg,
    );
    expect(id.groups).toEqual(["admins", "eng"]);
  });
});
