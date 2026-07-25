/**
 * Which nav entry should be highlighted for the current path.
 *
 * The previous logic prefix-matched each entry against its own href, which broke
 * in two ways:
 *
 *   - "Scan" pointed at /scans/new, so viewing a scan or a finding at
 *     /scans/<id> matched nothing and the sidebar highlighted no entry at all.
 *   - Settings entries matched exactly, so a sub-page such as
 *     /settings/integrations/ide highlighted nothing either.
 *
 * Both are fixed by resolving across all entries and letting the most specific
 * match win, so /scans/new highlights "New scan" while /scans/<id> highlights
 * "Scans" — even though /scans is also a prefix of /scans/new.
 */

/** True when href is the path itself or one of its parent segments. */
function matchesPath(pathname: string, href: string): boolean {
  if (pathname === href) return true;
  const prefix = href.endsWith("/") ? href : `${href}/`;
  return pathname.startsWith(prefix);
}

/**
 * The longest matching href, or undefined when nothing matches.
 * Comparing by length is enough here because a longer match is necessarily a
 * deeper path on the same branch.
 */
export function resolveActiveNavHref(
  pathname: string,
  hrefs: readonly string[],
): string | undefined {
  let best: string | undefined;
  for (const href of hrefs) {
    if (!matchesPath(pathname, href)) continue;
    if (best === undefined || href.length > best.length) best = href;
  }
  return best;
}
