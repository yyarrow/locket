import { eq } from "drizzle-orm";
import { db } from "@/db";
import { users } from "@/db/schema";
import { issueAuthToken } from "@/lib/auth-tokens";
import { assertEmailConfigured, sendVerificationEmail } from "@/lib/email";
import { hashAccountPassword } from "@/lib/passwords";
import { checkRateLimit } from "@/lib/rate-limit";
import { isEmail, isSameOrigin, jsonError, normalizeEmail } from "@/lib/request";

export async function POST(request: Request) {
  if (!isSameOrigin(request)) return jsonError("请求来源无效", 403);
  if ((process.env.REGISTRATION_MODE ?? "open") !== "open") return jsonError("暂未开放注册", 403);
  const body = await request.json().catch(() => null);
  const email = normalizeEmail(body?.email);
  const password = String(body?.password ?? "");
  if (!isEmail(email) || password.length < 12 || password.length > 256) {
    return jsonError("请输入有效邮箱和至少 12 位登录密码");
  }
  const allowedByIp = await checkRateLimit(request, "register-ip", 10, 60 * 60);
  const allowedByEmail = await checkRateLimit(request, "register-email", 3, 60 * 60, email);
  if (!allowedByIp || !allowedByEmail) return jsonError("请求过于频繁，请稍后再试", 429);
  try {
    assertEmailConfigured();
    const [existing] = await db.select().from(users).where(eq(users.email, email)).limit(1);
    let userId = existing?.id;
    if (!existing) {
      userId = crypto.randomUUID();
      await db.insert(users).values({ id: userId, email, passwordHash: await hashAccountPassword(password) });
    }
    let previewUrl: string | undefined;
    if (!existing?.emailVerifiedAt && userId) {
      previewUrl = await sendVerificationEmail(email, await issueAuthToken(userId, "verify"));
    }
    return Response.json({ ok: true, message: "如果邮箱可用，验证邮件已发送", previewUrl });
  } catch (error) {
    console.error("register failed", error);
    return jsonError("注册暂时不可用，请稍后再试", 503);
  }
}
