export async function jsonFetcher(url: string) {
  const res = await fetch(url);
  const data = await res.json().catch(() => null);

  if (!res.ok) {
    const message =
      data && typeof data === "object" && "error" in data
        ? String(data.error)
        : `Request failed with ${res.status}`;
    throw new Error(message);
  }

  return data;
}
