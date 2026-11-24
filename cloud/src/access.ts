// SPDX-License-Identifier: GPL-3.0-only
// Cloudflare Access JWT validation. Access in front of the hostname is not enough on its own: if the
// Worker were ever reachable another way (workers.dev, a preview URL, a second route) the header-less
// request would get straight in. So every admin/dashboard request must carry a valid
// `Cf-Access-Jwt-Assertion` for *this* application (aud) from *our* team (iss). Fails closed when
// ACCESS_TEAM_DOMAIN / ACCESS_AUD are not configured.
import { b64urlDecode, type Env } from "./util";

interface Jwk extends JsonWebKey {
  kid: string;
}
interface Jwks {
  keys: Jwk[];
}

const CACHE_MS = 10 * 60_000;
const REFETCH_MIN_MS = 60_000;
const SKEW_S = 60;
let cache: { url: string; keys: Map<string, CryptoKey>; at: number } | null = null;

export interface AccessIdentity {
  email: string;
}

export function teamOrigin(env: Env): string | null {
  const t = (env.ACCESS_TEAM_DOMAIN ?? "").trim().replace(/\/+$/, "");
  if (!t) return null;
  const host = t.replace(/^https?:\/\//, "");
  if (!/^[a-z0-9-]+\.cloudflareaccess\.com$/i.test(host)) return null;
  return `https://${host.toLowerCase()}`;
}

async function keysFor(origin: string, kid: string): Promise<CryptoKey | null> {
  const url = `${origin}/cdn-cgi/access/certs`;
  const now = Date.now();
  const fresh = cache && cache.url === url && now - cache.at < CACHE_MS;
  if (fresh && cache!.keys.has(kid)) return cache!.keys.get(kid)!;
  // Unknown kid: Access rotates keys, so refetch — but not more than once a minute.
  if (cache && cache.url === url && now - cache.at < REFETCH_MIN_MS) return cache.keys.get(kid) ?? null;
  const res = await fetch(url, { cf: { cacheTtl: 300 } } as RequestInit);
  if (!res.ok) return cache?.keys.get(kid) ?? null;
  const jwks = (await res.json()) as Jwks;
  const keys = new Map<string, CryptoKey>();
  for (const k of jwks.keys ?? []) {
    if (k.kty !== "RSA" || !k.kid) continue;
    keys.set(
      k.kid,
      await crypto.subtle.importKey("jwk", k, { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" }, false, [
        "verify",
      ]),
    );
  }
  cache = { url, keys, at: now };
  return keys.get(kid) ?? null;
}

/** Testing hook: forget cached keys. */
export function resetAccessCache(): void {
  cache = null;
}

export async function verifyAccess(req: Request, env: Env): Promise<AccessIdentity | null> {
  const origin = teamOrigin(env);
  const aud = (env.ACCESS_AUD ?? "").trim();
  if (!origin || !aud) return null;
  const jwt = req.headers.get("cf-access-jwt-assertion");
  if (!jwt) return null;
  const parts = jwt.split(".");
  if (parts.length !== 3) return null;
  let header: { alg?: string; kid?: string };
  let claims: { aud?: string | string[]; iss?: string; exp?: number; nbf?: number; email?: string; common_name?: string };
  try {
    header = JSON.parse(new TextDecoder().decode(b64urlDecode(parts[0]!)));
    claims = JSON.parse(new TextDecoder().decode(b64urlDecode(parts[1]!)));
  } catch {
    return null;
  }
  if (header.alg !== "RS256" || !header.kid) return null;
  const key = await keysFor(origin, header.kid);
  if (!key) return null;
  const ok = await crypto.subtle.verify(
    "RSASSA-PKCS1-v1_5",
    key,
    b64urlDecode(parts[2]!),
    new TextEncoder().encode(`${parts[0]}.${parts[1]}`),
  );
  if (!ok) return null;
  const now = Date.now() / 1000;
  const auds = Array.isArray(claims.aud) ? claims.aud : [claims.aud];
  if (!auds.includes(aud)) return null;
  if (claims.iss !== origin) return null;
  if (typeof claims.exp !== "number" || claims.exp < now - SKEW_S) return null;
  if (typeof claims.nbf === "number" && claims.nbf > now + SKEW_S) return null;
  const who = claims.email ?? (claims.common_name ? `service:${claims.common_name}` : null);
  return who ? { email: who } : null;
}
