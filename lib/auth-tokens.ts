import "server-only";

import { and, eq, gt, isNull } from "drizzle-orm";
import { db } from "@/db";
import { authTokens } from "@/db/schema";
import { randomToken } from "./encoding";
import { hashToken } from "./session";

export async function issueAuthToken(userId: string, purpose: "verify" | "reset") {
  const token = randomToken();
  await db.delete(authTokens).where(and(eq(authTokens.userId, userId), eq(authTokens.purpose, purpose)));
  await db.insert(authTokens).values({
    tokenHash: hashToken(token),
    userId,
    purpose,
    expiresAt: new Date(Date.now() + 60 * 60 * 1000),
  });
  return token;
}

export async function consumeAuthToken(token: string, purpose: "verify" | "reset") {
  const [record] = await db
    .update(authTokens)
    .set({ usedAt: new Date() })
    .where(
      and(
        eq(authTokens.tokenHash, hashToken(token)),
        eq(authTokens.purpose, purpose),
        gt(authTokens.expiresAt, new Date()),
        isNull(authTokens.usedAt),
      ),
    )
    .returning({ userId: authTokens.userId });
  return record?.userId ?? null;
}
