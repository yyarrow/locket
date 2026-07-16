import { AuthLinkPage } from "../auth-link-page";

export default async function VerifyPage({ searchParams }: { searchParams: Promise<{ token?: string }> }) {
  const { token = "" } = await searchParams;
  return <AuthLinkPage mode="verify" token={token} />;
}
