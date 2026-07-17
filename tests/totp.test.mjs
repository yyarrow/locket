import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";
import ts from "typescript";

const source = await readFile(new URL("../lib/totp.ts", import.meta.url), "utf8");
const compiled = ts.transpileModule(source, {
  compilerOptions: { module: ts.ModuleKind.ESNext, target: ts.ScriptTarget.ES2022 },
}).outputText;
const totp = await import(`data:text/javascript;base64,${Buffer.from(compiled).toString("base64")}`);

test("parses standard otpauth links without losing their account metadata", () => {
  const config = totp.parseTotpInput("otpauth://totp/Example:alice%40example.com?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&issuer=Example&algorithm=SHA1&digits=8&period=30");
  assert.deepEqual(config, {
    secret: "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ",
    algorithm: "SHA1",
    digits: 8,
    period: 30,
    issuer: "Example",
    account: "alice@example.com",
  });
  assert.match(totp.formatTotpInput(config), /^otpauth:\/\/totp\//u);
});

test("generates the RFC 6238 SHA-1 test vector", async () => {
  const code = await totp.generateTotp({
    secret: "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ",
    algorithm: "SHA1",
    digits: 8,
    period: 30,
  }, 59_000);
  assert.equal(code, "94287082");
});

test("accepts a manual Base32 key and rejects HOTP links", () => {
  assert.equal(totp.parseTotpInput("GEZD GNBV GY3T QOJQ").secret, "GEZDGNBVGY3TQOJQ");
  assert.throws(() => totp.parseTotpInput("otpauth://hotp/Example?secret=GEZDGNBVGY3TQOJQ&counter=1"), /仅支持/u);
});
