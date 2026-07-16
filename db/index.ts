import "server-only";

import { neon } from "@neondatabase/serverless";
import { drizzle, type NeonHttpDatabase } from "drizzle-orm/neon-http";
import * as schema from "./schema";

type Database = NeonHttpDatabase<typeof schema>;
let cached: Database | undefined;

export const db: Database = new Proxy({} as Database, {
  get(_target, property) {
    if (!cached) {
      const url = process.env.DATABASE_URL;
      if (!url) throw new Error("DATABASE_URL is not configured");
      cached = drizzle(neon(url), { schema });
    }
    const value = (cached as unknown as Record<string | symbol, unknown>)[property];
    return typeof value === "function" ? value.bind(cached) : value;
  },
});
