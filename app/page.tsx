import { VaultApp } from "./vault-app";
import { connection } from "next/server";

export default async function Home() {
  await connection();
  return <VaultApp />;
}
