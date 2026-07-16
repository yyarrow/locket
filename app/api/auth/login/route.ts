import { eq } from "drizzle-orm";
import { db } from "@/db";
import { users } from "@/db/schema";
import { hashAccountPassword, verifyAccountPassword } from "@/lib/passwords";
import { checkRateLimit } from "@/lib/rate-limit";
import { isSameOrigin, jsonError, normalizeEmail } from "@/lib/request";
import { createSession } from "@/lib/session";

export async function POST(request: Request) {
  if (!isSameOrigin(request)) return jsonError("请求来源无效", 403);
  const body = await request.json().catch(() => null);
  const email = normalizeEmail(body?.email);
  const password = String(body?.password ?? "");
  const allowedByIp = await checkRateLimit(request, "login-ip", 30, 15 * 60);
  const allowedByAccount = await checkRateLimit(request, "login-account", 8, 15 * 60, email);
  if (!allowedByIp || !allowedByAccount) return jsonError("尝试次数过多，请稍后再试", 429);
  const [user] = await db.select().from(users).where(eq(users.email, email)).limit(1);
  const valid = user ? await verifyAccountPassword(password, user.passwordHash) : (await hashAccountPassword(password), false);
  if (!user || !valid || user.disabled) return jsonError("邮箱或密码不正确", 401);
  if (!user.emailVerifiedAt) return jsonError("请先通过邮件验证账号", 403);
  await createSession(user.id, request);
  return Response.json({ ok: true, email: user.email });
}
