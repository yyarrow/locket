import { eq } from "drizzle-orm";
import { db } from "@/db";
import { users } from "@/db/schema";
import { consumeAuthToken } from "@/lib/auth-tokens";
import { isSameOrigin, jsonError } from "@/lib/request";

export async function POST(request: Request) {
  if (!isSameOrigin(request)) return jsonError("请求来源无效", 403);
  const body = await request.json().catch(() => null);
  const token = String(body?.token ?? "");
  if (!token) return jsonError("验证链接无效");
  const userId = await consumeAuthToken(token, "verify");
  if (!userId) return jsonError("验证链接无效或已过期");
  await db.update(users).set({ emailVerifiedAt: new Date() }).where(eq(users.id, userId));
  return Response.json({ ok: true });
}
