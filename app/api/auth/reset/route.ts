import { eq } from "drizzle-orm";
import { db } from "@/db";
import { sessions, users } from "@/db/schema";
import { consumeAuthToken } from "@/lib/auth-tokens";
import { hashAccountPassword } from "@/lib/passwords";
import { isSameOrigin, jsonError } from "@/lib/request";

export async function POST(request: Request) {
  if (!isSameOrigin(request)) return jsonError("请求来源无效", 403);
  const body = await request.json().catch(() => null);
  const token = String(body?.token ?? "");
  const password = String(body?.password ?? "");
  if (!token || password.length < 12 || password.length > 256) return jsonError("链接无效或密码不足 12 位");
  const userId = await consumeAuthToken(token, "reset");
  if (!userId) return jsonError("重置链接无效或已过期", 400);
  await db.update(users).set({ passwordHash: await hashAccountPassword(password) }).where(eq(users.id, userId));
  await db.delete(sessions).where(eq(sessions.userId, userId));
  return Response.json({ ok: true });
}
