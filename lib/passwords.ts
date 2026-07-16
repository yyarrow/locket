import "server-only";

import { timingSafeEqual } from "node:crypto";
import { argon2idAsync } from "@noble/hashes/argon2.js";
import { base64ToBytes, bytesToBase64, textEncoder } from "./encoding";

const PARAMETERS = { m: 19_456, t: 2, p: 1, dkLen: 32 } as const;

export async function hashAccountPassword(password: string): Promise<string> {
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const hash = await argon2idAsync(textEncoder.encode(password), salt, PARAMETERS);
  return `$argon2id$v=19$m=${PARAMETERS.m},t=${PARAMETERS.t},p=${PARAMETERS.p}$${bytesToBase64(salt)}$${bytesToBase64(hash)}`;
}

export async function verifyAccountPassword(password: string, encoded: string): Promise<boolean> {
  const match = /^\$argon2id\$v=19\$m=(\d+),t=(\d+),p=(\d+)\$([^$]+)\$([^$]+)$/u.exec(encoded);
  if (!match) return false;
  const [, memory, iterations, parallelism, saltText, hashText] = match;
  const expected = base64ToBytes(hashText);
  const actual = await argon2idAsync(textEncoder.encode(password), base64ToBytes(saltText), {
    m: Number(memory),
    t: Number(iterations),
    p: Number(parallelism),
    dkLen: expected.length,
  });
  return expected.length === actual.length && timingSafeEqual(Buffer.from(expected), Buffer.from(actual));
}
