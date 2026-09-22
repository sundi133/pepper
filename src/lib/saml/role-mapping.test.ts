import { describe, expect, it } from "vitest";
import {
  isRole,
  mapSamlRole,
  normalizeGroups,
  parseRoleMap,
} from "./role-mapping";

describe("parseRoleMap", () => {
  it("parses a valid group→role map", () => {
    expect(
      parseRoleMap('{"pepper-admins":"ADMIN","appsec":"SECURITY"}'),
    ).toEqual({ "pepper-admins": "ADMIN", appsec: "SECURITY" });
  });

  it("drops unknown roles and keeps valid ones", () => {
    expect(parseRoleMap('{"a":"ADMIN","b":"WIZARD"}')).toEqual({ a: "ADMIN" });
  });

  it("returns an empty map for empty, malformed, or non-object JSON", () => {
    expect(parseRoleMap("")).toEqual({});
    expect(parseRoleMap(undefined)).toEqual({});
    expect(parseRoleMap("not json")).toEqual({});
    expect(parseRoleMap('["ADMIN"]')).toEqual({});
    expect(parseRoleMap("null")).toEqual({});
  });
});

describe("normalizeGroups", () => {
  it("coerces string, array, and nullish claims", () => {
    expect(normalizeGroups("engineers")).toEqual(["engineers"]);
    expect(normalizeGroups(["a", " b ", ""])).toEqual(["a", "b"]);
    expect(normalizeGroups(undefined)).toEqual([]);
    expect(normalizeGroups(null)).toEqual([]);
  });
});

describe("mapSamlRole", () => {
  const roleMap = {
    "pepper-admins": "ADMIN",
    appsec: "SECURITY",
    engineers: "DEVELOPER",
  } as const;
  const cfg = { roleMap, defaultRole: "VIEWER" as const };

  it("maps a single matching group", () => {
    expect(mapSamlRole(["engineers"], cfg)).toBe("DEVELOPER");
  });

  it("picks the highest-privilege role when several groups match", () => {
    expect(mapSamlRole(["engineers", "pepper-admins", "appsec"], cfg)).toBe(
      "ADMIN",
    );
    expect(mapSamlRole(["engineers", "appsec"], cfg)).toBe("SECURITY");
  });

  it("falls back to the default role when nothing matches", () => {
    expect(mapSamlRole(["random", "other"], cfg)).toBe("VIEWER");
    expect(mapSamlRole([], cfg)).toBe("VIEWER");
    expect(mapSamlRole(undefined, cfg)).toBe("VIEWER");
  });

  it("accepts a scalar group claim", () => {
    expect(mapSamlRole("pepper-admins", cfg)).toBe("ADMIN");
  });
});

describe("isRole", () => {
  it("recognizes valid roles only", () => {
    expect(isRole("ADMIN")).toBe(true);
    expect(isRole("VIEWER")).toBe(true);
    expect(isRole("admin")).toBe(false);
    expect(isRole(123)).toBe(false);
  });
});
