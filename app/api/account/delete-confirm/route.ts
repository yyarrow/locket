import { eq } from "drizzle-orm";
import { db } from "@/db";
import { users } from "@/db/schema";
import { consumeAuthToken } from "@/lib/auth-tokens";
import { isSameOrigin, jsonError } from "@/lib/request";
import { clearSessionCookie } from "@/lib/session";

export async function POST(request: Request) {
  if (!isSameOrigin(request)) return jsonError("请求来源无效", 403);
  const body = await request.json().catch(() => null);
  const token = String(body?.token ?? "");
  if (!token) return jsonError("删除确认链接无效");
  const userId = await consumeAuthToken(token, "delete-account");
  if (!userId) return jsonError("删除确认链接无效或已过期");
  const [deleted] = await db.delete(users).where(eq(users.id, userId)).returning({ id: users.id });
  if (!deleted) return jsonError("账号不存在", 404);
  await clearSessionCookie();
  return Response.json({ ok: true });
}
