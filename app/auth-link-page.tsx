"use client";

import { FormEvent, useEffect, useState } from "react";
import Link from "next/link";

type Mode = "verify" | "reset";

async function post(url: string, body: Record<string, string>) {
  const response = await fetch(url, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(body),
  });
  const data = await response.json().catch(() => ({}));
  if (!response.ok) throw new Error(data.error ?? "请求失败");
}

export function AuthLinkPage({ mode, token }: { mode: Mode; token: string }) {
  const [status, setStatus] = useState<"idle" | "busy" | "success" | "error">(!token ? "error" : mode === "verify" ? "busy" : "idle");
  const [password, setPassword] = useState("");
  const [confirmation, setConfirmation] = useState("");
  const [message, setMessage] = useState(token ? "" : "链接缺少验证信息");

  useEffect(() => {
    if (mode !== "verify" || !token) return;
    void post("/api/auth/verify", { token })
      .then(() => setStatus("success"))
      .catch((error: unknown) => {
        setMessage(error instanceof Error ? error.message : "验证失败");
        setStatus("error");
      });
  }, [mode, token]);

  const reset = async (event: FormEvent) => {
    event.preventDefault();
    if (!token) return;
    if (password.length < 12) return setMessage("新登录密码至少需要 12 个字符");
    if (password !== confirmation) return setMessage("两次输入的密码不一致");
    setStatus("busy");
    setMessage("");
    try {
      await post("/api/auth/reset", { token, password });
      setPassword("");
      setConfirmation("");
      setStatus("success");
    } catch (error) {
      setMessage(error instanceof Error ? error.message : "重置失败");
      setStatus("error");
    }
  };

  const title = mode === "verify" ? "验证邮箱" : "重置登录密码";
  const success = mode === "verify" ? "邮箱验证完成" : "登录密码已更新";

  return <main className="auth-shell"><section className="auth-card account-card">
    <div className="brand-row"><div className="brand-mark">L</div><span>Locket</span></div>
    <div className="auth-copy"><span className="eyebrow">账号安全</span><h1>{status === "success" ? success : title}</h1>
      <p>{mode === "verify" ? "验证后即可登录并同步你的加密保险库。" : "这里只会更新账号登录密码，不会改变保险库主密码。"}</p>
    </div>
    {mode === "reset" && status !== "success" ? <form className="auth-form" onSubmit={reset}>
      <label>新登录密码<input type="password" minLength={12} maxLength={256} required autoComplete="new-password" value={password} onChange={(event) => setPassword(event.target.value)} /></label>
      <label>确认新密码<input type="password" minLength={12} maxLength={256} required autoComplete="new-password" value={confirmation} onChange={(event) => setConfirmation(event.target.value)} /></label>
      {message && <p className="form-error">{message}</p>}
      <button className="primary-button" disabled={status === "busy" || !token}>{status === "busy" ? "正在更新…" : "更新登录密码"}</button>
    </form> : status === "busy" ? <p className="link-status" role="status">正在验证链接…</p> : status === "error" ? <p className="form-error link-status">{message}</p> : <p className="link-status success-text">✓ 可以返回 Locket 登录了。</p>}
    <Link className="text-button link-button" href="/">返回 Locket</Link>
  </section><p className="auth-footer">服务端只保存加密后的保险库密文</p></main>;
}
