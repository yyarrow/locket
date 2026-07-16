import { AuthLinkPage } from "../auth-link-page";

export default async function ResetPage({ searchParams }: { searchParams: Promise<{ token?: string }> }) {
  const { token = "" } = await searchParams;
  return <AuthLinkPage mode="reset" token={token} />;
}
