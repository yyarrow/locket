import { isSameOrigin, jsonError } from "@/lib/request";
import { destroySession } from "@/lib/session";

export async function POST(request: Request) {
  if (!isSameOrigin(request)) return jsonError("请求来源无效", 403);
  await destroySession();
  return Response.json({ ok: true });
}
