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

export async function sendLoginEmail(email: string, token: string) {
  const url = `${appUrl()}/verify?token=${encodeURIComponent(token)}`;
  await deliver(email, "登录 Locket", `<p>点击下面的链接登录 Locket：</p><p><a href="${url}">登录 Locket</a></p><p>链接将在 15 分钟后失效，且只能使用一次。如果不是你发起的请求，请忽略此邮件。</p>`);
  return process.env.NODE_ENV === "production" ? undefined : url;
}

export async function sendAccountDeletionEmail(email: string, token: string) {
  const url = `${appUrl()}/delete-account?token=${encodeURIComponent(token)}`;
  await deliver(email, "确认删除 Locket 账号", `<p>我们收到了删除 Locket 账号的请求。</p><p><a href="${url}">检查并确认删除账号</a></p><p>打开链接后仍需再次确认。链接将在 30 分钟后失效，且只能使用一次。如果不是你发起的请求，请忽略此邮件。</p>`);
  return process.env.NODE_ENV === "production" ? undefined : url;
}
