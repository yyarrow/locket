"use client";

import { useEffect, useState } from "react";
import Link from "next/link";

async function post(url: string, body: Record<string, string>) {
  const response = await fetch(url, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(body),
  });
  const data = await response.json().catch(() => ({}));
  if (!response.ok) throw new Error(data.error ?? "请求失败");
}

export function AuthLinkPage({ token }: { token: string }) {
  const [status, setStatus] = useState<"busy" | "success" | "error">(token ? "busy" : "error");
  const [message, setMessage] = useState(token ? "" : "登录链接缺少验证信息");

  useEffect(() => {
    if (!token) return;
    window.history.replaceState(window.history.state, "", window.location.pathname);
    void post("/api/auth/verify", { token })
      .then(() => {
        setStatus("success");
        window.location.replace("/");
      })
      .catch((error: unknown) => {
        setMessage(error instanceof Error ? error.message : "验证失败");
        setStatus("error");
      });
  }, [token]);

  return <main className="auth-shell"><section className="auth-card account-card">
    <div className="brand-row"><div className="brand-mark">L</div><span>Locket</span></div>
    <div className="auth-copy"><span className="eyebrow">邮箱安全登录</span><h1>{status === "error" ? "登录链接不可用" : "正在登录 Locket"}</h1>
      <p>{status === "error" ? "请返回首页重新获取一次性登录链接。" : "验证完成后会自动进入你的加密保险库。"}</p>
    </div>
    {status === "error" ? <p className="form-error link-status">{message}</p> : <p className="link-status" role="status">{status === "success" ? "✓ 登录成功，正在进入 Locket…" : "正在验证一次性链接…"}</p>}
    {status === "error" && <Link className="text-button link-button" href="/">重新获取登录链接</Link>}
  </section><p className="auth-footer">服务端只保存加密后的保险库密文</p></main>;
}
