import { eq } from "drizzle-orm";
import { db } from "@/db";
import { vaults } from "@/db/schema";
import { getCurrentUser } from "@/lib/session";

export async function GET() {
  const user = await getCurrentUser();
  if (!user) return Response.json({ authenticated: false }, { headers: { "cache-control": "no-store" } });
  const [vault] = await db.select({ userId: vaults.userId }).from(vaults).where(eq(vaults.userId, user.id)).limit(1);
  return Response.json(
    { authenticated: true, email: user.email, verified: Boolean(user.verifiedAt), hasVault: Boolean(vault) },
    { headers: { "cache-control": "no-store" } },
  );
}
