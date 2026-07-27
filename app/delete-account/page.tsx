import { DeleteAccountPage } from "../delete-account-page";

export default async function DeleteAccount({ searchParams }: { searchParams: Promise<{ token?: string }> }) {
  const { token = "" } = await searchParams;
  return <DeleteAccountPage token={token} />;
}
