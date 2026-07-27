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

  const recoveryHex = created.recoveryCode.replace(/^LK2-/u, "").replaceAll("-", "");
  const legacyBody = Buffer.from(recoveryHex, "hex").toString("base64url");
  const legacyCode = `LK1-${legacyBody.match(/.{1,6}/gu).join("-")}`;
  const legacyRecovered = await cryptoModule.recoverAndRekeyVault(created.envelope, legacyCode, "legacy replacement password");
  assert.deepEqual(legacyRecovered.data, data);
});

test("changing the master password preserves data and invalidates the old password", async () => {
  const data = { items: [{ id: "one", secret: "preserved" }], createdAt: 1 };
  const created = await cryptoModule.createVault("current master password", data);
  const changed = await cryptoModule.changeVaultPassword(created.envelope, "current master password", "replacement master password");
  assert.deepEqual((await cryptoModule.unlockVault(changed, "replacement master password")).data, data);
  await assert.rejects(() => cryptoModule.unlockVault(changed, "current master password"));
  await assert.rejects(() => cryptoModule.changeVaultPassword(created.envelope, "wrong password", "replacement master password"));
});

test("rotating the recovery key invalidates the previous recovery code", async () => {
  const data = { items: [{ id: "one", secret: "preserved" }], createdAt: 1 };
  const created = await cryptoModule.createVault("current master password", data);
  const rotated = await cryptoModule.rotateVaultRecoveryKey(created.envelope, "current master password");
  assert.notEqual(rotated.recoveryCode, created.recoveryCode);
  await assert.rejects(() => cryptoModule.recoverAndRekeyVault(rotated.envelope, created.recoveryCode, "next password"));
  const recovered = await cryptoModule.recoverAndRekeyVault(rotated.envelope, rotated.recoveryCode, "next password");
  assert.deepEqual(recovered.data, data);
});
