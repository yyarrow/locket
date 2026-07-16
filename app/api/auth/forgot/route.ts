import { eq } from "drizzle-orm";
import { db } from "@/db";
import { users } from "@/db/schema";
import { issueAuthToken } from "@/lib/auth-tokens";
import { assertEmailConfigured, sendResetEmail } from "@/lib/email";
import { checkRateLimit } from "@/lib/rate-limit";
import { isSameOrigin, jsonError, normalizeEmail } from "@/lib/request";

export async function POST(request: Request) {
  if (!isSameOrigin(request)) return jsonError("请求来源无效", 403);
  const body = await request.json().catch(() => null);
  const email = normalizeEmail(body?.email);
  const allowedByIp = await checkRateLimit(request, "forgot-ip", 10, 60 * 60);
  const allowedByAccount = await checkRateLimit(request, "forgot-account", 3, 60 * 60, email);
  if (!allowedByIp || !allowedByAccount) return jsonError("请求过于频繁，请稍后再试", 429);
  try {
    assertEmailConfigured();
    const [user] = await db.select().from(users).where(eq(users.email, email)).limit(1);
    const previewUrl = user ? await sendResetEmail(email, await issueAuthToken(user.id, "reset")) : undefined;
    return Response.json({ ok: true, message: "如果账号存在，重置邮件已发送", previewUrl });
  } catch (error) {
    console.error("forgot password failed", error);
    return jsonError("暂时无法发送邮件，请稍后再试", 503);
  }
}
