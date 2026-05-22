import { bitbucketGet, parseBitbucketErrorBody } from "./bitbucket-api";
import type { BitbucketAuth } from "./bitbucket-api";
import { normalizeBitbucketUuid } from "./parse-bitbucket-repo-input";

export type BitbucketRepoListItem = {
  uuid: string;
  fullName: string;
  workspace: string;
  slug: string;
  name: string;
  defaultBranch: string;
  language: string | null;
  private: boolean;
  cloneUrl: string;
  alreadyConnected: boolean;
};

type BitbucketApiRepo = {
  uuid?: string;
  slug?: string;
  name?: string;
  full_name?: string;
  is_private?: boolean;
  language?: string;
  mainbranch?: { name?: string };
  links?: { clone?: Array<{ name?: string; href?: string }> };
};

type BitbucketRepoPage = {
  values?: BitbucketApiRepo[];
  next?: string | null;
};

function httpsCloneFromLinks(links: BitbucketApiRepo["links"]): string | null {
  const clones = links?.clone;
  if (!Array.isArray(clones)) return null;
  const https = clones.find((c) => c.name === "https" && c.href);
  return https?.href?.trim() || null;
}

export async function listBitbucketRepositoriesInWorkspace(
  auth: BitbucketAuth,
  workspace: string,
  connectedRepoUuids: Set<string>,
): Promise<BitbucketRepoListItem[]> {
  const items: BitbucketRepoListItem[] = [];
  let path = `/repositories/${encodeURIComponent(workspace)}?pagelen=100&sort=-updated_on`;

  for (let page = 0; page < 20 && path; page++) {
    const res = await bitbucketGet<BitbucketRepoPage>(auth, path);
    if (!res.ok) {
      const detail = parseBitbucketErrorBody(res.data, res.raw);
      throw new Error(
        detail || `Bitbucket API error (${res.status}) listing repositories`,
      );
    }

    const batch = res.data?.values ?? [];
    for (const r of batch) {
      if (!r.uuid || !r.slug) continue;
      const uuid = normalizeBitbucketUuid(r.uuid);
      const fullName = r.full_name || `${workspace}/${r.slug}`;
      const cloneUrl =
        httpsCloneFromLinks(r.links) ||
        `https://bitbucket.org/${workspace}/${r.slug}.git`;
      items.push({
        uuid,
        fullName,
        workspace,
        slug: r.slug,
        name: r.name || r.slug,
        defaultBranch: r.mainbranch?.name || "main",
        language: r.language ?? null,
        private: Boolean(r.is_private),
        cloneUrl,
        alreadyConnected: connectedRepoUuids.has(uuid),
      });
    }

    const next = res.data?.next;
    if (!next) break;
    try {
      const u = new URL(next);
      path = `${u.pathname}${u.search}`;
    } catch {
      break;
    }
  }

  return items;
}
