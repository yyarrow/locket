import { argon2idAsync } from "@noble/hashes/argon2.js";
import {
  base64ToBytes,
  base64UrlToBytes,
  bytesToBase64,
  bytesToBase64Url,
  textDecoder,
  textEncoder,
} from "./encoding";

export type VaultEnvelope = {
  formatVersion: 2;
  ciphertext: string;
  iv: string;
  wrappedKey: string;
  wrapIv: string;
  recoveryWrappedKey: string;
  recoveryWrapIv: string;
  kdfSalt: string;
  kdfName: "argon2id";
  kdfMemory: 19_456;
  kdfIterations: 2;
  kdfParallelism: 1;
  itemCount: number;
  revision: number;
};

const KDF = { m: 19_456, t: 2, p: 1, dkLen: 32 } as const;

async function importAesKey(bytes: Uint8Array) {
  return crypto.subtle.importKey("raw", bytes as BufferSource, { name: "AES-GCM" }, false, ["encrypt", "decrypt"]);
}

async function deriveMasterKey(password: string, salt: Uint8Array) {
  const bytes = await argon2idAsync(textEncoder.encode(password), salt, KDF);
  return importAesKey(bytes);
}

async function encryptBytes(bytes: Uint8Array, key: CryptoKey) {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ciphertext = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, bytes as BufferSource);
  return { ciphertext: bytesToBase64(new Uint8Array(ciphertext)), iv: bytesToBase64(iv) };
}

async function decryptBytes(ciphertext: string, iv: string, key: CryptoKey) {
  const clear = await crypto.subtle.decrypt(
    { name: "AES-GCM", iv: base64ToBytes(iv) },
    key,
    base64ToBytes(ciphertext),
  );
  return new Uint8Array(clear);
}

function recoveryCodeFromBytes(bytes: Uint8Array) {
  const body = bytesToBase64Url(bytes);
  return `LK1-${body.match(/.{1,6}/gu)?.join("-") ?? body}`;
}

function recoveryBytesFromCode(code: string) {
  const normalized = code.trim().replace(/^LK1-/iu, "").replaceAll("-", "");
  const bytes = base64UrlToBytes(normalized);
  if (bytes.length !== 32) throw new Error("恢复密钥格式无效");
  return bytes;
}

export async function createVault<T extends { items: unknown[] }>(password: string, data: T) {
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const dataKeyBytes = crypto.getRandomValues(new Uint8Array(32));
  const recoveryBytes = crypto.getRandomValues(new Uint8Array(32));
  const [masterKey, dataKey, recoveryKey] = await Promise.all([
    deriveMasterKey(password, salt),
    importAesKey(dataKeyBytes),
    importAesKey(recoveryBytes),
  ]);
  const [payload, masterWrapped, recoveryWrapped] = await Promise.all([
    encryptBytes(textEncoder.encode(JSON.stringify(data)), dataKey),
    encryptBytes(dataKeyBytes, masterKey),
    encryptBytes(dataKeyBytes, recoveryKey),
  ]);
  const envelope: VaultEnvelope = {
    formatVersion: 2,
    ciphertext: payload.ciphertext,
    iv: payload.iv,
    wrappedKey: masterWrapped.ciphertext,
    wrapIv: masterWrapped.iv,
    recoveryWrappedKey: recoveryWrapped.ciphertext,
    recoveryWrapIv: recoveryWrapped.iv,
    kdfSalt: bytesToBase64(salt),
    kdfName: "argon2id",
    kdfMemory: KDF.m,
    kdfIterations: KDF.t,
    kdfParallelism: KDF.p,
    itemCount: data.items.length,
    revision: 0,
  };
  return { envelope, dataKey, recoveryCode: recoveryCodeFromBytes(recoveryBytes) };
}

export async function unlockVault<T>(envelope: VaultEnvelope, password: string) {
  const masterKey = await deriveMasterKey(password, base64ToBytes(envelope.kdfSalt));
  const dataKey = await importAesKey(await decryptBytes(envelope.wrappedKey, envelope.wrapIv, masterKey));
  const clear = await decryptBytes(envelope.ciphertext, envelope.iv, dataKey);
  return { data: JSON.parse(textDecoder.decode(clear)) as T, dataKey };
}

export async function recoverAndRekeyVault<T>(envelope: VaultEnvelope, recoveryCode: string, newPassword: string) {
  const recoveryKey = await importAesKey(recoveryBytesFromCode(recoveryCode));
  const dataKeyBytes = await decryptBytes(envelope.recoveryWrappedKey, envelope.recoveryWrapIv, recoveryKey);
  const dataKey = await importAesKey(dataKeyBytes);
  const data = JSON.parse(textDecoder.decode(await decryptBytes(envelope.ciphertext, envelope.iv, dataKey))) as T;
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const masterKey = await deriveMasterKey(newPassword, salt);
  const wrapped = await encryptBytes(dataKeyBytes, masterKey);
  return {
    data,
    dataKey,
    envelope: { ...envelope, kdfSalt: bytesToBase64(salt), wrappedKey: wrapped.ciphertext, wrapIv: wrapped.iv },
  };
}

export async function encryptVaultData<T extends { items: unknown[] }>(data: T, dataKey: CryptoKey, envelope: VaultEnvelope) {
  const payload = await encryptBytes(textEncoder.encode(JSON.stringify(data)), dataKey);
  return { ...envelope, ciphertext: payload.ciphertext, iv: payload.iv, itemCount: data.items.length };
}

export function isVaultEnvelope(value: unknown): value is VaultEnvelope {
  if (!value || typeof value !== "object") return false;
  const input = value as Partial<VaultEnvelope>;
  return input.formatVersion === 2 && input.kdfName === "argon2id" &&
    typeof input.ciphertext === "string" && typeof input.iv === "string" &&
    typeof input.wrappedKey === "string" && typeof input.wrapIv === "string" &&
    typeof input.recoveryWrappedKey === "string" && typeof input.recoveryWrapIv === "string" &&
    typeof input.kdfSalt === "string" && Number.isInteger(input.revision);
}
