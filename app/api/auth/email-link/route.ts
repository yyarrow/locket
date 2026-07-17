import { eq } from "drizzle-orm";
import { db } from "@/db";
import { users } from "@/db/schema";
import { issueAuthToken } from "@/lib/auth-tokens";
import { assertEmailConfigured, sendLoginEmail } from "@/lib/email";
import { checkRateLimit } from "@/lib/rate-limit";
import { isEmail, isSameOrigin, jsonError, normalizeEmail } from "@/lib/request";

export async function POST(request: Request) {
  if (!isSameOrigin(request)) return jsonError("请求来源无效", 403);
  const body = await request.json().catch(() => null);
  const email = normalizeEmail(body?.email);
  if (!isEmail(email)) return jsonError("请输入有效邮箱");
  const allowedByIp = await checkRateLimit(request, "email-link-ip", 10, 60 * 60);
  const allowedByEmail = await checkRateLimit(request, "email-link-email", 3, 60 * 60, email);
  if (!allowedByIp || !allowedByEmail) return jsonError("请求过于频繁，请稍后再试", 429);

  try {
    assertEmailConfigured();
    let [user] = await db.select({ id: users.id, disabled: users.disabled }).from(users).where(eq(users.email, email)).limit(1);
    if (!user && (process.env.REGISTRATION_MODE ?? "open") !== "open") return jsonError("暂未开放新账号", 403);
    if (!user) {
      await db.insert(users).values({ id: crypto.randomUUID(), email }).onConflictDoNothing();
      [user] = await db.select({ id: users.id, disabled: users.disabled }).from(users).where(eq(users.email, email)).limit(1);
    }
    if (!user || user.disabled) return Response.json({ ok: true, message: "登录链接已发送" });
    const userId = user.id;
    const previewUrl = await sendLoginEmail(email, await issueAuthToken(userId));
    return Response.json({ ok: true, message: "登录链接已发送", previewUrl });
  } catch (error) {
    console.error("email login failed", error);
    return jsonError("暂时无法发送登录邮件，请稍后再试", 503);
  }
}
