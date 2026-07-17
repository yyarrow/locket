import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

const read = (path) => readFile(new URL(path, import.meta.url), "utf8");

test("encrypts the vault in the browser with a random data key and recovery key", async () => {
  const source = await read("../lib/vault-crypto.ts");
  assert.match(source, /argon2idAsync/);
  assert.match(source, /AES-GCM/);
  assert.match(source, /dataKeyBytes = crypto\.getRandomValues/);
  assert.match(source, /recoveryWrappedKey/);
  assert.match(source, /recoverAndRekeyVault/);
});

test("sync schema contains ciphertext metadata but no vault plaintext fields", async () => {
  const schema = await read("../db/schema.ts");
  assert.match(schema, /ciphertext: text/);
  assert.match(schema, /wrappedKey: text/);
  assert.match(schema, /recoveryWrappedKey: text/);
  assert.doesNotMatch(schema, /username:|password:|notes:/);
});

test("account and session safeguards remain enabled", async () => {
  const [emailLink, verify, session, limiter, vaultRoute] = await Promise.all([
    read("../app/api/auth/email-link/route.ts"),
    read("../app/api/auth/verify/route.ts"),
    read("../lib/session.ts"),
    read("../lib/rate-limit.ts"),
    read("../app/api/vault/route.ts"),
  ]);
  assert.match(emailLink, /REGISTRATION_MODE/);
  assert.match(emailLink, /isSameOrigin/);
  assert.match(emailLink, /checkRateLimit/);
  assert.match(verify, /createSession/);
  assert.match(session, /httpOnly: true/);
  assert.match(session, /sameSite: "lax"/);
  assert.match(limiter, /on conflict \(key\) do update/);
  assert.match(vaultRoute, /eq\(vaults\.revision, payload\.revision\)/);
});

test("client keeps local safety controls without plaintext persistence", async () => {
  const source = await read("../app/vault-app.tsx");
  assert.match(source, /AUTO_LOCK_MS/);
  assert.match(source, /主密码至少需要 12 个字符/);
  assert.match(source, /加密备份/);
  assert.match(source, /navigator\.clipboard/);
  assert.doesNotMatch(source, /localStorage|sessionStorage|indexedDB/);
  assert.doesNotMatch(source, /登录密码|\/api\/auth\/login|\/api\/auth\/register/);
});
