"use client";

import Link from "next/link";
import { useState } from "react";

export function DeleteAccountPage({ token }: { token: string }) {
  const [status, setStatus] = useState<"ready" | "busy" | "success" | "error">(token ? "ready" : "error");
  const [message, setMessage] = useState(token ? "" : "删除确认链接缺少验证信息");

  const confirmDeletion = async () => {
    setStatus("busy");
    setMessage("");
    try {
      const response = await fetch("/api/account/delete-confirm", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ token }),
      });
      const result = await response.json().catch(() => ({}));
      if (!response.ok) throw new Error(result.error ?? "删除失败");
      setStatus("success");
    } catch (error) {
      setMessage(error instanceof Error ? error.message : "删除失败");
      setStatus("error");
    }
  };

  return <main className="auth-shell"><section className="auth-card account-card deletion-page">
    <div className="brand-row"><div className="brand-mark">L</div><span>Locket</span></div>
    <div className="auth-copy"><span className="eyebrow">账号与数据</span><h1>{status === "success" ? "账号已删除" : "确认删除账号"}</h1>
      <p>{status === "success" ? "你的账号、全部会话以及云端加密保险库已经永久删除。" : "此操作会永久删除账号、全部登录会话和云端密文，无法撤销。请确认你已经导出所需备份。"}</p>
    </div>
    {status === "success" ? <Link className="primary-button deletion-home" href="/">返回 Locket</Link> : <>
      {message && <p className="form-error">{message}</p>}
      <button className="deletion-confirm" disabled={status === "busy" || !token} onClick={() => void confirmDeletion()}>{status === "busy" ? "正在永久删除…" : "永久删除我的账号和数据"}</button>
      <Link className="text-button link-button" href="/">取消并返回</Link>
    </>}
  </section><p className="auth-footer">删除操作需要邮箱一次性链接确认</p></main>;
}
