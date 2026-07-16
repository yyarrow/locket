import "server-only";

export function authSecret() {
  const value = process.env.AUTH_SECRET;
  if (!value && process.env.NODE_ENV === "production") {
    throw new Error("AUTH_SECRET is not configured");
  }
  return value ?? "locket-development-secret";
}
