import { eq } from "drizzle-orm";
import { db } from "@/db";
import { users } from "@/db/schema";
import { consumeAuthToken } from "@/lib/auth-tokens";
import { isSameOrigin, jsonError } from "@/lib/request";
import { createSession } from "@/lib/session";

export async function POST(request: Request) {
  if (!isSameOrigin(request)) return jsonError("请求来源无效", 403);
  const body = await request.json().catch(() => null);
  const token = String(body?.token ?? "");
  if (!token) return jsonError("登录链接无效");
  const userId = await consumeAuthToken(token);
  if (!userId) return jsonError("登录链接无效或已过期");
  const [user] = await db.update(users).set({ emailVerifiedAt: new Date() }).where(eq(users.id, userId)).returning({ disabled: users.disabled });
  if (!user || user.disabled) return jsonError("账号不可用", 403);
  await createSession(userId, request);
  return Response.json({ ok: true });
}
