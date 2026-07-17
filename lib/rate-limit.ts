import "server-only";

import { createHash } from "node:crypto";
import { sql } from "drizzle-orm";
import { db } from "@/db";
import { authSecret } from "./secrets";

export async function checkRateLimit(request: Request, scope: string, limit: number, windowSeconds: number, discriminator = "") {
  const forwarded = request.headers.get("x-forwarded-for")?.split(",")[0]?.trim() ?? "unknown";
  const secret = authSecret();
  const identity = discriminator || forwarded;
  const digest = createHash("sha256").update(`${secret}:${scope}:${identity}`).digest("hex");
  const key = `${scope}:${digest}`;
  const expiresAt = new Date(Date.now() + windowSeconds * 1000);
  const rows = await db.execute<{ count: number }>(sql`
    insert into rate_limits (key, count, window_start, expires_at)
    values (${key}, 1, now(), ${expiresAt})
    on conflict (key) do update set
      count = case when rate_limits.expires_at <= now() then 1 else rate_limits.count + 1 end,
      window_start = case when rate_limits.expires_at <= now() then now() else rate_limits.window_start end,
      expires_at = case when rate_limits.expires_at <= now() then ${expiresAt} else rate_limits.expires_at end
    returning count
  `);
  return Number(rows.rows[0]?.count ?? limit + 1) <= limit;
}
