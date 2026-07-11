import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

const appUrl = new URL("../app/vault-app.tsx", import.meta.url);

test("uses browser-native authenticated encryption and local persistence", async () => {
  const source = await readFile(appUrl, "utf8");
  assert.match(source, /AES-GCM/);
  assert.match(source, /PBKDF2/);
  assert.match(source, /SHA-256/);
  assert.match(source, /310_000/);
  assert.match(source, /indexedDB\.open/);
  assert.doesNotMatch(source, /fetch\(|XMLHttpRequest|WebSocket/);
});

test("keeps the MVP safeguards in place", async () => {
  const source = await readFile(appUrl, "utf8");
  assert.match(source, /AUTO_LOCK_MS/);
  assert.match(source, /主密码至少需要 12 个字符/);
  assert.match(source, /加密备份/);
  assert.match(source, /navigator\.clipboard/);
});
