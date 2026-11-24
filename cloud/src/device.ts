// SPDX-License-Identifier: GPL-3.0-only
// Device-facing endpoints: enroll (one-time code → bearer token) and config pull. Tokens and codes
// are stored as SHA-256 only (they're high-entropy random values, so a fast hash is the right tool
// and keeps us far below the 10 ms CPU limit).
import { HttpError, newToken, normalizeEnrollCode, nowIso, readBody, setting, sha256hex, uuid7, type Env } from "./util";

export interface Device {
  id: string;
  name: string;
  site_id: string | null;
}

export async function authDevice(req: Request, env: Env): Promise<Device> {
  const m = /^Bearer ([A-Za-z0-9_-]{40,64})$/.exec(req.headers.get("authorization") ?? "");
  if (!m) throw new HttpError(401, "device token required");
  const hash = await sha256hex(m[1]!);
  const d = await env.DB.prepare(
    "SELECT d.id, d.name, d.site_id FROM device_tokens t JOIN devices d ON d.id = t.device_id" +
      " WHERE t.token_hash = ? AND t.revoked_at IS NULL AND d.revoked_at IS NULL",
  )
    .bind(hash)
    .first<Device>();
  if (!d) throw new HttpError(401, "unknown or revoked device token");
  return d;
}

function info(v: unknown): Record<string, string> {
  const out: Record<string, string> = {};
  if (v && typeof v === "object") {
    for (const k of ["version", "platform", "hostname", "model"]) {
      const x = (v as Record<string, unknown>)[k];
      if (typeof x === "string") out[k] = x.slice(0, 80);
    }
  }
  return out;
}

export async function handleEnroll(req: Request, env: Env): Promise<Response> {
  let body: { code?: unknown; info?: unknown };
  try {
    body = JSON.parse(await readBody(req, 4096, 4096));
  } catch (e) {
    if (e instanceof HttpError) throw e;
    throw new HttpError(400, "invalid JSON");
  }
  const code = typeof body.code === "string" ? normalizeEnrollCode(body.code) : null;
  if (!code) throw new HttpError(400, "enrollment code format: XXXXX-XXXXX");
  const now = nowIso();
  // Claim the code atomically: single use, unexpired.
  const claimed = await env.DB.prepare(
    "UPDATE enroll_codes SET used_at = ?1 WHERE code_hash = ?2 AND used_at IS NULL AND expires_at > ?1" +
      " RETURNING device_name, site_id",
  )
    .bind(now, await sha256hex(code))
    .first<{ device_name: string; site_id: string | null }>();
  if (!claimed) throw new HttpError(401, "invalid, used or expired enrollment code");
  const id = uuid7();
  const token = newToken();
  await env.DB.batch([
    env.DB.prepare(
      "INSERT INTO devices(id, name, site_id, created_at, last_seen_at, info) VALUES (?, ?, ?, ?, ?, ?)",
    ).bind(id, claimed.device_name, claimed.site_id, now, now, JSON.stringify(info(body.info))),
    env.DB.prepare("INSERT INTO device_tokens(token_hash, device_id, created_at) VALUES (?, ?, ?)").bind(
      await sha256hex(token),
      id,
      now,
    ),
    env.DB.prepare(
      "INSERT INTO usage_meter(day, requests, rows_written) VALUES (?1, 1, 3) ON CONFLICT(day) DO UPDATE" +
        " SET requests = requests + 1, rows_written = rows_written + 3",
    ).bind(now.slice(0, 10)),
  ]);
  return Response.json({ device_id: id, name: claimed.device_name, site_id: claimed.site_id, token });
}

/** GET /api/v1/config — what the dashboard pushes down. ETag = config version (cheap 304s). */
export async function handleConfig(req: Request, env: Env, dev: Device): Promise<Response> {
  const version = await setting(env.DB, "config_version", "1");
  const etag = `"v${version}"`;
  if (req.headers.get("if-none-match") === etag) return new Response(null, { status: 304, headers: { etag } });
  const [site, profiles] = await env.DB.batch([
    env.DB.prepare("SELECT id, name FROM sites WHERE id = ?").bind(dev.site_id ?? ""),
    env.DB.prepare("SELECT body FROM profiles ORDER BY id"),
  ]);
  return Response.json(
    {
      version: Number(version),
      device: { id: dev.id, name: dev.name },
      site: (site!.results[0] as { id: string; name: string } | undefined) ?? null,
      profiles: (profiles!.results as { body: string }[]).map((p) => JSON.parse(p.body)),
    },
    { headers: { etag } },
  );
}
