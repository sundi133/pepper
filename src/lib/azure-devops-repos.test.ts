import { describe, expect, it, vi, beforeEach } from "vitest";

const azureGet = vi.fn();

vi.mock("./azure-devops-api", async (importOriginal) => {
  const actual = await importOriginal<typeof import("./azure-devops-api")>();
  return {
    ...actual,
    azureGet: (...args: unknown[]) => azureGet(...args),
  };
});

import { listAzureDevOpsRepositoriesInOrganization } from "./azure-devops-repos";

const auth = { organization: "acme", pat: "pat" };

function repo(id: string, name: string, project = "team") {
  return {
    id,
    name,
    project: { name: project },
    remoteUrl: `https://dev.azure.com/acme/${project}/_git/${name}`,
    defaultBranch: "refs/heads/main",
  };
}

function okPage(value: unknown[]) {
  return { ok: true, status: 200, data: { value }, raw: "" };
}

beforeEach(() => azureGet.mockReset());

describe("listAzureDevOpsRepositoriesInOrganization", () => {
  it("maps repositories and marks the connected ones", async () => {
    azureGet.mockResolvedValueOnce(okPage([repo("1", "a"), repo("2", "b")]));
    const items = await listAzureDevOpsRepositoriesInOrganization(
      auth,
      new Set(["2"]),
    );
    expect(items.map((i) => i.id)).toEqual(["1", "2"]);
    expect(items[0]).toMatchObject({
      fullName: "team/a",
      azureOrganization: "acme",
      defaultBranch: "main",
      alreadyConnected: false,
    });
    expect(items[1].alreadyConnected).toBe(true);
  });

  it("dedupes when ADO ignores paging and returns the full list every page", async () => {
    // A full first page (>= top would loop; simulate the endpoint ignoring
    // $skip by returning the SAME repos on the second call).
    const full = [repo("1", "a"), repo("2", "b")];
    azureGet.mockResolvedValue(okPage(full));
    const items = await listAzureDevOpsRepositoriesInOrganization(
      auth,
      new Set(),
    );
    // Even though the mock would return forever, dedup + no-new-page stop
    // yields each repo exactly once.
    expect(items.map((i) => i.id)).toEqual(["1", "2"]);
  });

  it("skips repositories missing an id, name, project, or clone URL", async () => {
    azureGet.mockResolvedValueOnce(
      okPage([
        { id: "1", name: "a", project: { name: "team" } }, // no remoteUrl/webUrl
        { id: "", name: "b", project: { name: "team" }, remoteUrl: "x" },
        repo("3", "c"),
      ]),
    );
    const items = await listAzureDevOpsRepositoriesInOrganization(
      auth,
      new Set(),
    );
    expect(items.map((i) => i.id)).toEqual(["3"]);
  });

  it("throws with the parsed error detail on a non-ok response", async () => {
    azureGet.mockResolvedValueOnce({
      ok: false,
      status: 401,
      data: { message: "TF400813: not authorized" },
      raw: "",
    });
    await expect(
      listAzureDevOpsRepositoriesInOrganization(auth, new Set()),
    ).rejects.toThrow("TF400813: not authorized");
  });
});
