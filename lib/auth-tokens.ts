import "server-only";

import { and, eq, gt, isNull } from "drizzle-orm";
import { db } from "@/db";
import { authTokens } from "@/db/schema";
import { randomToken } from "./encoding";
import { hashToken } from "./session";

const LOGIN_TOKEN_TTL_MS = 15 * 60 * 1000;

export async function issueAuthToken(userId: string) {
  const token = randomToken();
  await db.delete(authTokens).where(and(eq(authTokens.userId, userId), eq(authTokens.purpose, "login")));
  await db.insert(authTokens).values({
    tokenHash: hashToken(token),
    userId,
    purpose: "login",
    expiresAt: new Date(Date.now() + LOGIN_TOKEN_TTL_MS),
  });
  return token;
}

export async function consumeAuthToken(token: string) {
  const [record] = await db
    .update(authTokens)
    .set({ usedAt: new Date() })
    .where(
      and(
        eq(authTokens.tokenHash, hashToken(token)),
        eq(authTokens.purpose, "login"),
        gt(authTokens.expiresAt, new Date()),
        isNull(authTokens.usedAt),
      ),
    )
    .returning({ userId: authTokens.userId });
  return record?.userId ?? null;
}
