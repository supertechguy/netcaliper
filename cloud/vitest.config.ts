// SPDX-License-Identifier: GPL-3.0-only
import { cloudflareTest, readD1Migrations } from "@cloudflare/vitest-plugin";
import { defineConfig } from "vitest/config";

export default defineConfig(async () => {
  const migrations = await readD1Migrations("migrations");
  return {
    plugins: [
      cloudflareTest({
        wrangler: { configPath: "./wrangler.jsonc" },
        miniflare: {
          // Test-only Access settings; production values are passed at deploy time.
          bindings: {
            TEST_MIGRATIONS: migrations,
            ACCESS_TEAM_DOMAIN: "netcaliper-test.cloudflareaccess.com",
            ACCESS_AUD: "test-aud",
          },
        },
      }),
    ],
    test: { setupFiles: ["./test/setup.ts"] },
  };
});
