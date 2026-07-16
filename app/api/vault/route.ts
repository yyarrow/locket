import { and, eq } from "drizzle-orm";
import { db } from "@/db";
import { vaults } from "@/db/schema";
import { isSameOrigin, jsonError } from "@/lib/request";
import { getCurrentUser } from "@/lib/session";

type VaultPayload = {
  formatVersion: 2;
  ciphertext: string;
  iv: string;
  wrappedKey: string;
  wrapIv: string;
  recoveryWrappedKey: string;
  recoveryWrapIv: string;
  kdfSalt: string;
  kdfName: "argon2id";
  kdfMemory: number;
  kdfIterations: number;
  kdfParallelism: number;
  itemCount: number;
  revision: number;
};

function validBase64(value: unknown, max: number) {
  return typeof value === "string" && value.length > 0 && value.length <= max && /^[A-Za-z0-9+/]+={0,2}$/u.test(value);
}

function parseVault(value: unknown): VaultPayload | null {
  if (!value || typeof value !== "object") return null;
  const input = value as Partial<VaultPayload>;
  if (
    input.formatVersion !== 2 || input.kdfName !== "argon2id" || input.kdfMemory !== 19_456 ||
    input.kdfIterations !== 2 || input.kdfParallelism !== 1 || !Number.isInteger(input.revision) ||
    !Number.isInteger(input.itemCount) || input.itemCount! < 0 || input.itemCount! > 500 ||
    !validBase64(input.ciphertext, 7_000_000) || !validBase64(input.iv, 64) ||
    !validBase64(input.wrappedKey, 256) || !validBase64(input.wrapIv, 64) ||
    !validBase64(input.recoveryWrappedKey, 256) || !validBase64(input.recoveryWrapIv, 64) ||
    !validBase64(input.kdfSalt, 128)
  ) return null;
  return input as VaultPayload;
}

export async function GET() {
  const user = await getCurrentUser();
  if (!user || !user.verifiedAt) return jsonError("请先登录", 401);
  const [vault] = await db.select().from(vaults).where(eq(vaults.userId, user.id)).limit(1);
  return Response.json({ vault: vault ?? null }, { headers: { "cache-control": "no-store" } });
}

export async function PUT(request: Request) {
  if (!isSameOrigin(request)) return jsonError("请求来源无效", 403);
  const user = await getCurrentUser();
  if (!user || !user.verifiedAt) return jsonError("请先登录", 401);
  const payload = parseVault(await request.json().catch(() => null));
  if (!payload) return jsonError("保险库数据格式无效");
  const values = { ...payload, updatedAt: new Date() };
  if (payload.revision === 0) {
    const [created] = await db.insert(vaults).values({ ...values, userId: user.id, revision: 1 }).onConflictDoNothing().returning({ revision: vaults.revision });
    if (!created) return jsonError("保险库已在其他设备创建，请刷新", 409);
    return Response.json({ ok: true, revision: created.revision });
  }
  const [updated] = await db
    .update(vaults)
    .set({ ...values, revision: payload.revision + 1 })
    .where(and(eq(vaults.userId, user.id), eq(vaults.revision, payload.revision)))
    .returning({ revision: vaults.revision });
  if (!updated) return jsonError("保险库已在其他设备更新，请重新解锁后再试", 409);
  return Response.json({ ok: true, revision: updated.revision });
}
