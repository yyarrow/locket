import assert from "node:assert/strict";
import test from "node:test";
import { build } from "esbuild";

const [{ text }] = (await build({
  entryPoints: [new URL("../lib/vault-crypto.ts", import.meta.url).pathname],
  bundle: true,
  write: false,
  platform: "browser",
  format: "esm",
  target: "es2022",
})).outputFiles;
const cryptoModule = await import(`data:text/javascript;base64,${Buffer.from(text).toString("base64")}`);

test("vault encryption round-trips and rejects the wrong master password", async () => {
  const data = { items: [{ id: "one", secret: "encrypted-value" }], createdAt: 1 };
  const created = await cryptoModule.createVault("correct horse battery staple", data);
  const unlocked = await cryptoModule.unlockVault(created.envelope, "correct horse battery staple");
  assert.deepEqual(unlocked.data, data);
  await assert.rejects(() => cryptoModule.unlockVault(created.envelope, "wrong password"));
});

test("recovery key rewraps the same vault under a new master password", async () => {
  const data = { items: [{ id: "one", secret: "still-encrypted" }], createdAt: 1 };
  const created = await cryptoModule.createVault("old master password", data);
  const recovered = await cryptoModule.recoverAndRekeyVault(created.envelope, created.recoveryCode, "new master password");
  assert.deepEqual(recovered.data, data);
  assert.deepEqual((await cryptoModule.unlockVault(recovered.envelope, "new master password")).data, data);
  await assert.rejects(() => cryptoModule.unlockVault(recovered.envelope, "old master password"));
});
