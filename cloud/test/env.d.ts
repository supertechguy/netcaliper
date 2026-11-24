// SPDX-License-Identifier: GPL-3.0-only
import type { D1Migration } from "cloudflare:test";
import type { Env as WorkerEnv } from "../src/util";

declare global {
  namespace Cloudflare {
    interface Env extends WorkerEnv {
      TEST_MIGRATIONS: D1Migration[];
    }
    interface GlobalProps {
      mainModule: typeof import("../src/index");
    }
  }
}
