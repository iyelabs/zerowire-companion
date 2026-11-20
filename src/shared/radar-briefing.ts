const origin = "https://radar.cloudflare.com";

export function radarBriefingIdentity(value: string) {
  let url: URL;
  try { url = new URL(value); } catch { return null; }
  if (url.origin !== origin || url.username || url.password) return null;
  const match = url.pathname.match(/^\/(?:security\/)?zero-wire\/([a-z0-9][a-z0-9-]*)\/?$/);
  if (!match) return null;
  // Keep the original public ID and all database foreign keys across Radar moves.
  return {
    id: `${origin}/security/zero-wire/${match[1]}`,
    canonicalUrl: `${origin}${url.pathname.replace(/\/$/, "")}`,
  };
}
