import "server-only";

import { createHash } from "node:crypto";
import { and, eq, gt, inArray } from "drizzle-orm";
import { cookies } from "next/headers";
import { db } from "@/db";
import { sessions, users } from "@/db/schema";
import { randomToken } from "./encoding";
import { authSecret } from "./secrets";

const LEGACY_COOKIE_NAME = "locket_session";
const COOKIE_NAME = process.env.NODE_ENV === "production" ? "__Host-locket_session" : LEGACY_COOKIE_NAME;
const SESSION_TTL_SECONDS = 60 * 60 * 24 * 30;
const SESSION_IDLE_TTL_SECONDS = 60 * 60 * 24 * 7;
const SESSION_TOUCH_INTERVAL_SECONDS = 60 * 15;

function sessionCookieOptions(maxAge: number) {
  return {
    httpOnly: true,
    secure: process.env.NODE_ENV === "production",
    sameSite: "lax" as const,
    maxAge,
    path: "/",
  };
}

function sessionTokens(store: Awaited<ReturnType<typeof cookies>>): string[] {
  return [...new Set([
    store.get(COOKIE_NAME)?.value,
    COOKIE_NAME === LEGACY_COOKIE_NAME ? undefined : store.get(LEGACY_COOKIE_NAME)?.value,
  ].filter((token): token is string => Boolean(token)))];
}

function clearSessionCookies(store: Awaited<ReturnType<typeof cookies>>): void {
  store.set(COOKIE_NAME, "", sessionCookieOptions(0));
  if (COOKIE_NAME !== LEGACY_COOKIE_NAME) store.set(LEGACY_COOKIE_NAME, "", sessionCookieOptions(0));
}

export function sessionIdleCutoff(now = new Date()): Date {
  return new Date(now.getTime() - SESSION_IDLE_TTL_SECONDS * 1000);
}

export function hashToken(token: string): string {
  return createHash("sha256").update(token).digest("hex");
}

export async function createSession(userId: string, request: Request): Promise<void> {
  const store = await cookies();
  const previousSessionIds = sessionTokens(store).map(hashToken);
  const token = randomToken();
  const expiresAt = new Date(Date.now() + SESSION_TTL_SECONDS * 1000);
  const forwarded = request.headers.get("x-forwarded-for")?.split(",")[0]?.trim() ?? "unknown";
  const secret = authSecret();
  const ipHash = createHash("sha256").update(`${secret}:${forwarded}`).digest("hex");
  await db.insert(sessions).values({
    id: hashToken(token),
    userId,
    expiresAt,
    userAgent: request.headers.get("user-agent")?.slice(0, 300),
    ipHash,
  });
  if (previousSessionIds.length > 0) await db.delete(sessions).where(inArray(sessions.id, previousSessionIds));
  store.set(COOKIE_NAME, token, sessionCookieOptions(SESSION_TTL_SECONDS));
  if (COOKIE_NAME !== LEGACY_COOKIE_NAME) store.set(LEGACY_COOKIE_NAME, "", sessionCookieOptions(0));
}

export async function destroySession(): Promise<void> {
  const store = await cookies();
  const ids = sessionTokens(store).map(hashToken);
  if (ids.length > 0) await db.delete(sessions).where(inArray(sessions.id, ids));
  clearSessionCookies(store);
}

export async function clearSessionCookie(): Promise<void> {
  clearSessionCookies(await cookies());
}

export async function getCurrentSessionId(): Promise<string | null> {
  const [token] = sessionTokens(await cookies());
  return token ? hashToken(token) : null;
}

export async function getCurrentUser() {
  const store = await cookies();
  const [token] = sessionTokens(store);
  if (!token) return null;
  const usingLegacyCookie = COOKIE_NAME !== LEGACY_COOKIE_NAME && !store.get(COOKIE_NAME)?.value;
  const now = new Date();
  const sessionId = hashToken(token);
  const [record] = await db
    .select({
      id: users.id,
      email: users.email,
      verifiedAt: users.emailVerifiedAt,
      disabled: users.disabled,
      expiresAt: sessions.expiresAt,
      lastSeenAt: sessions.lastSeenAt,
    })
    .from(sessions)
    .innerJoin(users, eq(users.id, sessions.userId))
    .where(and(
      eq(sessions.id, sessionId),
      gt(sessions.expiresAt, now),
      gt(sessions.lastSeenAt, sessionIdleCutoff(now)),
    ))
    .limit(1);
  if (!record || record.disabled) return null;
  if (record.lastSeenAt.getTime() < now.getTime() - SESSION_TOUCH_INTERVAL_SECONDS * 1000) {
    await db.update(sessions).set({ lastSeenAt: now }).where(eq(sessions.id, sessionId));
  }
  if (usingLegacyCookie) {
    const remainingSeconds = Math.max(1, Math.floor((record.expiresAt.getTime() - now.getTime()) / 1000));
    store.set(COOKIE_NAME, token, sessionCookieOptions(remainingSeconds));
    store.set(LEGACY_COOKIE_NAME, "", sessionCookieOptions(0));
  }
  return { id: record.id, email: record.email, verifiedAt: record.verifiedAt, disabled: record.disabled };
}
