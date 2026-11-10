// SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
// SPDX-License-Identifier: Apache-2.0

// GitHub Actions selects the version before deployment using its read-only token.
export const TAG_RE = /^v\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?$/;
const UA = "erpc-installer-selector";

interface Release {
  tag_name: string;
  draft: boolean;
  prerelease: boolean;
  published_at: string;
}

function publishedRelease(value: unknown): value is Release {
  if (!value || typeof value !== "object") return false;
  const release = value as Partial<Release>;
  return typeof release.tag_name === "string" && TAG_RE.test(release.tag_name)
    && release.draft === false && typeof release.prerelease === "boolean"
    && typeof release.published_at === "string"
    && Number.isFinite(Date.parse(release.published_at));
}

export async function resolveLatest(repo: string, fetcher: typeof fetch = fetch): Promise<{ tag: string; source: string } | null> {
  const headers = { "user-agent": UA, accept: "application/vnd.github+json" };
  const base = `https://api.github.com/repos/${repo}/releases`;
  try {
    const stable = await fetcher(`${base}/latest`, { headers });
    if (stable.ok) {
      const release: unknown = await stable.json();
      return publishedRelease(release) && !release.prerelease
        ? { tag: release.tag_name, source: "github-latest" } : null;
    }
    // Only a missing stable release enables the prerelease fallback. Outages
    // and rate limits must not silently change the version selected.
    if (stable.status !== 404) return null;

    let newest: Release | null = null;
    for (let page = 1; ; page++) {
      const response = await fetcher(`${base}?per_page=100&page=${page}`, {
        headers,
      });
      if (!response.ok) return null;
      const releases: unknown = await response.json();
      if (!Array.isArray(releases)) return null;
      for (const release of releases) {
        if (publishedRelease(release) && release.prerelease
          && (!newest || Date.parse(release.published_at) > Date.parse(newest.published_at))) {
          newest = release;
        }
      }
      if (releases.length < 100) break;
    }
    return newest ? { tag: newest.tag_name, source: "github-prerelease" } : null;
  } catch {
    return null;
  }
}
