import { argon2idAsync } from "@noble/hashes/argon2.js";
import {
  base64ToBytes,
  base64UrlToBytes,
  bytesToBase64,
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

async function unwrapDataKeyBytes(envelope: VaultEnvelope, password: string) {
  const masterKey = await deriveMasterKey(password, base64ToBytes(envelope.kdfSalt));
  return decryptBytes(envelope.wrappedKey, envelope.wrapIv, masterKey);
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
  const body = Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0")).join("").toUpperCase();
  return `LK2-${body.match(/.{1,8}/gu)?.join("-") ?? body}`;
}

function legacyRecoveryCandidates(code: string) {
  const raw = code.trim().replace(/^LK1-/iu, "");
  const separatorCount = [...raw].filter((character) => character === "-").length;
  if (!raw || raw.length > 64 || separatorCount > 12 || !/^[A-Za-z0-9_-]+$/u.test(raw)) return [];
  const bodies = new Set<string>();
  const visit = (index: number, body: string) => {
    if (body.length > 43) return;
    if (index === raw.length) {
      if (body.length === 43) bodies.add(body);
      return;
    }
    const character = raw[index];
    if (character === "-") visit(index + 1, body);
    visit(index + 1, body + character);
  };
  visit(0, "");
  return [...bodies].map((body) => base64UrlToBytes(body)).filter((bytes) => bytes.length === 32);
}

function recoveryByteCandidates(code: string) {
  const trimmed = code.trim();
  if (/^LK2-/iu.test(trimmed)) {
    const normalized = trimmed.replace(/^LK2-/iu, "").replaceAll("-", "");
    if (!/^[0-9a-f]{64}$/iu.test(normalized)) throw new Error("恢复密钥格式无效");
    return [Uint8Array.from(normalized.match(/.{2}/gu) ?? [], (pair) => Number.parseInt(pair, 16))];
  }
  const candidates = legacyRecoveryCandidates(trimmed);
  if (candidates.length === 0) throw new Error("恢复密钥格式无效");
  return candidates;
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
  let dataKeyBytes: Uint8Array | undefined;
  for (const candidate of recoveryByteCandidates(recoveryCode)) {
    try {
      const recoveryKey = await importAesKey(candidate);
      dataKeyBytes = await decryptBytes(envelope.recoveryWrappedKey, envelope.recoveryWrapIv, recoveryKey);
      break;
    } catch {
      // LK1 used "-" both as data and as a visual separator, so legacy codes can
      // have more than one valid decoding candidate. Only one can unwrap the DEK.
    }
  }
  if (!dataKeyBytes) throw new Error("恢复密钥无效，或保险库已损坏");
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

export async function changeVaultPassword(envelope: VaultEnvelope, currentPassword: string, newPassword: string) {
  const dataKeyBytes = await unwrapDataKeyBytes(envelope, currentPassword);
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const masterKey = await deriveMasterKey(newPassword, salt);
  const wrapped = await encryptBytes(dataKeyBytes, masterKey);
  return { ...envelope, kdfSalt: bytesToBase64(salt), wrappedKey: wrapped.ciphertext, wrapIv: wrapped.iv };
}

export async function rotateVaultRecoveryKey(envelope: VaultEnvelope, currentPassword: string) {
  const dataKeyBytes = await unwrapDataKeyBytes(envelope, currentPassword);
  const recoveryBytes = crypto.getRandomValues(new Uint8Array(32));
  const recoveryKey = await importAesKey(recoveryBytes);
  const wrapped = await encryptBytes(dataKeyBytes, recoveryKey);
  return {
    envelope: { ...envelope, recoveryWrappedKey: wrapped.ciphertext, recoveryWrapIv: wrapped.iv },
    recoveryCode: recoveryCodeFromBytes(recoveryBytes),
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
