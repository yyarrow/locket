import { and, desc, eq, gt } from "drizzle-orm";
import { db } from "@/db";
import { sessions } from "@/db/schema";
import { isSameOrigin, jsonError } from "@/lib/request";
import { clearSessionCookie, getCurrentSessionId, getCurrentUser } from "@/lib/session";

export async function GET() {
  const user = await getCurrentUser();
  const currentSessionId = await getCurrentSessionId();
  if (!user || !currentSessionId) return jsonError("请先登录", 401);
  const records = await db
    .select({ id: sessions.id, userAgent: sessions.userAgent, createdAt: sessions.createdAt, lastSeenAt: sessions.lastSeenAt })
    .from(sessions)
    .where(and(eq(sessions.userId, user.id), gt(sessions.expiresAt, new Date())))
    .orderBy(desc(sessions.lastSeenAt));
  return Response.json({
    sessions: records.map((session) => ({ ...session, current: session.id === currentSessionId })),
  }, { headers: { "cache-control": "no-store" } });
}

export async function DELETE(request: Request) {
  if (!isSameOrigin(request)) return jsonError("请求来源无效", 403);
  const user = await getCurrentUser();
  const currentSessionId = await getCurrentSessionId();
  if (!user || !currentSessionId) return jsonError("请先登录", 401);
  const body = await request.json().catch(() => null);
  const sessionId = String(body?.sessionId ?? "");
  if (!/^[a-f0-9]{64}$/u.test(sessionId)) return jsonError("会话标识无效");
  const [removed] = await db.delete(sessions)
    .where(and(eq(sessions.id, sessionId), eq(sessions.userId, user.id)))
    .returning({ id: sessions.id });
  if (!removed) return jsonError("会话不存在", 404);
  if (sessionId === currentSessionId) await clearSessionCookie();
  return Response.json({ ok: true, current: sessionId === currentSessionId });
}
