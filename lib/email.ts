import "server-only";

import type { Transporter } from "nodemailer";

function appUrl() {
  if (process.env.APP_URL) return process.env.APP_URL.replace(/\/$/u, "");
  if (process.env.VERCEL_PROJECT_PRODUCTION_URL) return `https://${process.env.VERCEL_PROJECT_PRODUCTION_URL}`;
  if (process.env.VERCEL_URL) return `https://${process.env.VERCEL_URL}`;
  return "http://localhost:3000";
}

export function assertEmailConfigured() {
  const hasProvider = Boolean(process.env.RESEND_API_KEY || process.env.SMTP_HOST);
  if (process.env.NODE_ENV === "production" && (!hasProvider || !process.env.EMAIL_FROM)) {
    throw new Error("Email delivery is not configured");
  }
}

let transporter: Transporter | null = null;

async function deliver(to: string, subject: string, html: string) {
  if (!process.env.EMAIL_FROM || (!process.env.RESEND_API_KEY && !process.env.SMTP_HOST)) {
    console.info(`[Locket email preview] ${subject} → ${to}\n${html.replace(/<[^>]+>/gu, " ")}`);
    return;
  }
  if (process.env.RESEND_API_KEY) {
    const response = await fetch("https://api.resend.com/emails", {
      method: "POST",
      headers: { authorization: `Bearer ${process.env.RESEND_API_KEY}`, "content-type": "application/json" },
      body: JSON.stringify({ from: process.env.EMAIL_FROM, to: [to], subject, html }),
    });
    if (!response.ok) throw new Error(`Email provider returned ${response.status}`);
    return;
  }
  if (!transporter) {
    const { createTransport } = await import("nodemailer");
    const port = Number(process.env.SMTP_PORT ?? 465);
    transporter = createTransport({
      host: process.env.SMTP_HOST,
      port,
      secure: process.env.SMTP_SECURE ? process.env.SMTP_SECURE === "true" : port === 465,
      auth: process.env.SMTP_USER ? { user: process.env.SMTP_USER, pass: process.env.SMTP_PASS } : undefined,
    });
  }
  await transporter.sendMail({ from: process.env.EMAIL_FROM, to, subject, html });
}

export async function sendVerificationEmail(email: string, token: string) {
  const url = `${appUrl()}/verify?token=${encodeURIComponent(token)}`;
  await deliver(email, "验证你的 Locket 邮箱", `<p>点击下面的链接验证邮箱并开始使用 Locket：</p><p><a href="${url}">验证邮箱</a></p><p>链接将在 1 小时后失效。</p>`);
  return process.env.NODE_ENV === "production" ? undefined : url;
}

export async function sendResetEmail(email: string, token: string) {
  const url = `${appUrl()}/reset?token=${encodeURIComponent(token)}`;
  await deliver(email, "重置你的 Locket 登录密码", `<p>点击下面的链接重置登录密码：</p><p><a href="${url}">重置登录密码</a></p><p>这不会重置保险库主密码。链接将在 1 小时后失效。</p>`);
  return process.env.NODE_ENV === "production" ? undefined : url;
}
