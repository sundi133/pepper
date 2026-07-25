import { describe, it, expect } from "vitest";
import { effectiveApiKeyRole, MAX_API_KEY_ROLE } from "./api-key-role";
import { ROLE_HIERARCHY } from "./constants";

/**
 * API keys carry no role of their own, so the role they may exercise is derived
 * from their creator and capped. A credential sitting in a CI config must not be
 * able to do more than run scans.
 */
describe("effectiveApiKeyRole", () => {
  it("caps a privileged creator at the API key ceiling", () => {
    expect(effectiveApiKeyRole("ADMIN")).toBe("DEVELOPER");
    expect(effectiveApiKeyRole("SECURITY")).toBe("DEVELOPER");
  });

  it("leaves a creator at the ceiling unchanged", () => {
    expect(effectiveApiKeyRole("DEVELOPER")).toBe("DEVELOPER");
  });

  it("does not promote a creator below the ceiling", () => {
    // A key issued by a VIEWER must still not be able to start scans.
    expect(effectiveApiKeyRole("VIEWER")).toBe("VIEWER");
  });

  it("never exceeds the declared ceiling for any known role", () => {
    for (const role of ["ADMIN", "SECURITY", "DEVELOPER", "VIEWER"]) {
      expect(ROLE_HIERARCHY[effectiveApiKeyRole(role)]).toBeLessThanOrEqual(
        ROLE_HIERARCHY[MAX_API_KEY_ROLE],
      );
    }
  });

  it("never returns more than the creator holds", () => {
    for (const role of ["ADMIN", "SECURITY", "DEVELOPER", "VIEWER"]) {
      expect(ROLE_HIERARCHY[effectiveApiKeyRole(role)]).toBeLessThanOrEqual(
        ROLE_HIERARCHY[role],
      );
    }
  });

  it("treats an unrecognised role as least privileged", () => {
    // Fail closed: an unknown value must not be assumed to be privileged.
    expect(effectiveApiKeyRole("SUPERUSER")).toBe("VIEWER");
    expect(effectiveApiKeyRole("")).toBe("VIEWER");
  });

  it("keeps the ceiling below roles that manage the organisation", () => {
    // Guards the intent: keys must not reach ADMIN or SECURITY operations.
    expect(ROLE_HIERARCHY[MAX_API_KEY_ROLE]).toBeLessThan(
      ROLE_HIERARCHY.SECURITY,
    );
    expect(ROLE_HIERARCHY[MAX_API_KEY_ROLE]).toBeLessThan(ROLE_HIERARCHY.ADMIN);
  });

  it("keeps the ceiling high enough to create scans", () => {
    // Scan creation requires DEVELOPER; a lower ceiling would break CI.
    expect(ROLE_HIERARCHY[MAX_API_KEY_ROLE]).toBeGreaterThanOrEqual(
      ROLE_HIERARCHY.DEVELOPER,
    );
  });
});
