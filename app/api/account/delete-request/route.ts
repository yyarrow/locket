import { issueAuthToken } from "@/lib/auth-tokens";
import { assertEmailConfigured, sendAccountDeletionEmail } from "@/lib/email";
import { checkRateLimit } from "@/lib/rate-limit";
import { isSameOrigin, jsonError } from "@/lib/request";
import { getCurrentUser } from "@/lib/session";

export async function POST(request: Request) {
  if (!isSameOrigin(request)) return jsonError("请求来源无效", 403);
  const user = await getCurrentUser();
  if (!user || !user.verifiedAt) return jsonError("请先登录", 401);
  if (!await checkRateLimit(request, "delete-account", 3, 60 * 60, user.id)) return jsonError("请求过于频繁，请稍后再试", 429);
  try {
    assertEmailConfigured();
    const token = await issueAuthToken(user.id, "delete-account");
    const previewUrl = await sendAccountDeletionEmail(user.email, token);
    return Response.json({ ok: true, previewUrl });
  } catch (error) {
    console.error("account deletion email failed", error);
    return jsonError("暂时无法发送确认邮件，请稍后再试", 503);
  }
}
