// SPDX-License-Identifier: GPL-3.0-only
export interface Env {
  DB: D1Database;
  ASSETS: Fetcher;
  ACCESS_TEAM_DOMAIN: string;
  ACCESS_AUD: string;
  DAILY_ROW_BUDGET: string;
}

export const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;

export const nowIso = (d: Date = new Date()): string => d.toISOString();
export const utcDay = (d: Date = new Date()): string => d.toISOString().slice(0, 10);

export async function sha256hex(s: string): Promise<string> {
  const buf = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(s));
  return [...new Uint8Array(buf)].map((b) => b.toString(16).padStart(2, "0")).join("");
}

export function b64url(bytes: Uint8Array): string {
  let s = "";
  for (const b of bytes) s += String.fromCharCode(b);
  return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

export function b64urlDecode(s: string): Uint8Array {
  const pad = s.replace(/-/g, "+").replace(/_/g, "/") + "===".slice((s.length + 3) % 4);
  const bin = atob(pad);
  return Uint8Array.from(bin, (c) => c.charCodeAt(0));
}

/** Device bearer token: 32 random bytes. Only its SHA-256 is stored. */
export function newToken(): string {
  return b64url(crypto.getRandomValues(new Uint8Array(32)));
}

// Crockford base32: no I, L, O, U — easy to read off a dashboard and type on the uConsole keyboard.
const B32 = "0123456789ABCDEFGHJKMNPQRSTVWXYZ";

/** Enrollment code: 10 symbols = 50 bits, shown as XXXXX-XXXXX. 15 min TTL, single use. */
export function newEnrollCode(): string {
  const bytes = crypto.getRandomValues(new Uint8Array(10));
  const s = [...bytes].map((b) => B32[b & 31]).join("");
  return `${s.slice(0, 5)}-${s.slice(5)}`;
}

export function normalizeEnrollCode(code: string): string | null {
  const s = code
    .toUpperCase()
    .replace(/[\s-]/g, "")
    .replace(/O/g, "0")
    .replace(/[IL]/g, "1");
  return /^[0-9A-HJKMNP-TV-Z]{10}$/.test(s) ? s : null;
}

export function uuid7(): string {
  const b = crypto.getRandomValues(new Uint8Array(16));
  const ms = Date.now();
  for (let i = 0; i < 6; i++) b[i] = Math.floor(ms / 2 ** (8 * (5 - i))) & 0xff;
  b[6] = (b[6]! & 0x0f) | 0x70;
  b[8] = (b[8]! & 0x3f) | 0x80;
  const h = [...b].map((x) => x.toString(16).padStart(2, "0")).join("");
  return `${h.slice(0, 8)}-${h.slice(8, 12)}-${h.slice(12, 16)}-${h.slice(16, 20)}-${h.slice(20)}`;
}

export async function setting(db: D1Database, key: string, fallback: string): Promise<string> {
  const r = await db.prepare("SELECT value FROM settings WHERE key = ?").bind(key).first<{ value: string }>();
  return r?.value ?? fallback;
}

/** Read the request body with a hard cap (bytes), decompressing gzip if sent that way. */
export async function readBody(req: Request, maxWire: number, maxPlain: number): Promise<string> {
  const declared = Number(req.headers.get("content-length") ?? "0");
  if (declared > maxWire) throw new HttpError(413, "request too large");
  if (!req.body) return "";
  let stream: ReadableStream<Uint8Array> = req.body;
  let wire = 0;
  stream = stream.pipeThrough(
    new TransformStream<Uint8Array, Uint8Array>({
      transform(chunk, ctl) {
        wire += chunk.byteLength;
        if (wire > maxWire) throw new HttpError(413, "request too large");
        ctl.enqueue(chunk);
      },
    }),
  );
  if ((req.headers.get("content-encoding") ?? "").toLowerCase() === "gzip") {
    stream = stream.pipeThrough(new DecompressionStream("gzip"));
  }
  const parts: Uint8Array[] = [];
  let plain = 0;
  const reader = stream.getReader();
  for (;;) {
    let r: ReadableStreamReadResult<Uint8Array>;
    try {
      r = await reader.read();
    } catch (e) {
      if (e instanceof HttpError) throw e;
      throw new HttpError(400, "body is not valid gzip");
    }
    if (r.done) break;
    plain += r.value.byteLength;
    if (plain > maxPlain) throw new HttpError(413, "request too large once decompressed");
    parts.push(r.value);
  }
  const all = new Uint8Array(plain);
  let o = 0;
  for (const p of parts) {
    all.set(p, o);
    o += p.byteLength;
  }
  return new TextDecoder("utf-8").decode(all);
}

export class HttpError extends Error {
  constructor(
    readonly status: 400 | 401 | 403 | 404 | 409 | 413 | 415 | 429 | 503,
    message: string,
  ) {
    super(message);
  }
}
