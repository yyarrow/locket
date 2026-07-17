export type TotpAlgorithm = "SHA1" | "SHA256" | "SHA512";

export type TotpConfig = {
  secret: string;
  algorithm: TotpAlgorithm;
  digits: 6 | 8;
  period: number;
  issuer?: string;
  account?: string;
};

const BASE32_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

function normalizeSecret(value: string) {
  return value.trim().toUpperCase().replace(/\s+/gu, "").replaceAll("-", "").replace(/=+$/u, "");
}

function base32ToBytes(value: string) {
  const normalized = normalizeSecret(value);
  if (!normalized || /[^A-Z2-7]/u.test(normalized)) throw new Error("TOTP 密钥不是有效的 Base32 格式");

  let buffer = 0;
  let bits = 0;
  const output: number[] = [];
  for (const character of normalized) {
    buffer = (buffer << 5) | BASE32_ALPHABET.indexOf(character);
    bits += 5;
    if (bits >= 8) {
      bits -= 8;
      output.push((buffer >>> bits) & 0xff);
    }
  }
  return new Uint8Array(output);
}

function parseAlgorithm(value: string | null): TotpAlgorithm {
  const normalized = (value ?? "SHA1").toUpperCase().replaceAll("-", "");
  if (normalized === "SHA1" || normalized === "SHA256" || normalized === "SHA512") return normalized;
  throw new Error("仅支持 SHA1、SHA256 或 SHA512 的 TOTP");
}

function parseDigits(value: string | null): 6 | 8 {
  const digits = Number(value ?? 6);
  if (digits === 6 || digits === 8) return digits;
  throw new Error("TOTP 验证码位数必须是 6 或 8");
}

function parsePeriod(value: string | null) {
  const period = Number(value ?? 30);
  if (!Number.isInteger(period) || period < 1 || period > 3600) throw new Error("TOTP 更新周期无效");
  return period;
}

function validateSecret(value: string) {
  const normalized = normalizeSecret(value);
  if (base32ToBytes(normalized).length < 10) throw new Error("TOTP 密钥至少需要 80 位");
  return normalized;
}

export function parseTotpInput(input: string): TotpConfig {
  const trimmed = input.trim();
  if (!trimmed) throw new Error("请输入 TOTP 密钥");

  if (!trimmed.toLowerCase().startsWith("otpauth://")) {
    return { secret: validateSecret(trimmed), algorithm: "SHA1", digits: 6, period: 30 };
  }

  let url: URL;
  try {
    url = new URL(trimmed);
  } catch {
    throw new Error("otpauth 链接格式无效");
  }
  if (url.protocol !== "otpauth:" || url.hostname.toLowerCase() !== "totp") {
    throw new Error("仅支持 otpauth://totp 链接");
  }

  let label: string;
  try {
    label = decodeURIComponent(url.pathname.slice(1));
  } catch {
    throw new Error("otpauth 账号标签格式无效");
  }
  const separator = label.indexOf(":");
  const labelIssuer = separator >= 0 ? label.slice(0, separator).trim() : "";
  const account = (separator >= 0 ? label.slice(separator + 1) : label).trim();
  const issuer = (url.searchParams.get("issuer") ?? labelIssuer).trim();

  return {
    secret: validateSecret(url.searchParams.get("secret") ?? ""),
    algorithm: parseAlgorithm(url.searchParams.get("algorithm")),
    digits: parseDigits(url.searchParams.get("digits")),
    period: parsePeriod(url.searchParams.get("period")),
    ...(issuer ? { issuer } : {}),
    ...(account ? { account } : {}),
  };
}

export function formatTotpInput(config: TotpConfig) {
  if (!config.issuer && !config.account) return config.secret;
  const label = [config.issuer, config.account].filter(Boolean).join(":");
  const params = new URLSearchParams({
    secret: config.secret,
    algorithm: config.algorithm,
    digits: String(config.digits),
    period: String(config.period),
  });
  if (config.issuer) params.set("issuer", config.issuer);
  return `otpauth://totp/${encodeURIComponent(label)}?${params.toString()}`;
}

function hashName(algorithm: TotpAlgorithm) {
  return algorithm === "SHA1" ? "SHA-1" : algorithm === "SHA256" ? "SHA-256" : "SHA-512";
}

export async function generateTotp(config: TotpConfig, timestamp = Date.now()) {
  const counter = Math.floor(timestamp / 1000 / config.period);
  const message = new Uint8Array(8);
  const view = new DataView(message.buffer);
  view.setUint32(0, Math.floor(counter / 0x1_0000_0000), false);
  view.setUint32(4, counter >>> 0, false);

  const key = await crypto.subtle.importKey(
    "raw",
    base32ToBytes(config.secret),
    { name: "HMAC", hash: hashName(config.algorithm) },
    false,
    ["sign"],
  );
  const digest = new Uint8Array(await crypto.subtle.sign("HMAC", key, message));
  const offset = digest[digest.length - 1] & 0x0f;
  const binary = ((digest[offset] & 0x7f) << 24) |
    ((digest[offset + 1] & 0xff) << 16) |
    ((digest[offset + 2] & 0xff) << 8) |
    (digest[offset + 3] & 0xff);
  return String(binary % (10 ** config.digits)).padStart(config.digits, "0");
}

export function getTotpRemaining(period: number, timestamp = Date.now()) {
  return period - (Math.floor(timestamp / 1000) % period);
}
