// SPDX-License-Identifier: GPL-3.0-only
import { applyD1Migrations, reset } from "cloudflare:test";
import { env } from "cloudflare:workers";
import { afterEach, beforeEach, vi } from "vitest";
import { resetAccessCache } from "../src/access";

beforeEach(async () => {
  await reset();
  await applyD1Migrations(env.DB, env.TEST_MIGRATIONS);
  resetAccessCache();
});
afterEach(() => {
  vi.restoreAllMocks();
});
