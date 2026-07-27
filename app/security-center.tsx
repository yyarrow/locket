"use client";

import { FormEvent, useEffect, useState } from "react";
import { changeVaultPassword, rotateVaultRecoveryKey, type VaultEnvelope } from "@/lib/vault-crypto";

type SessionInfo = {
  id: string;
  userAgent: string | null;
  createdAt: string;
  lastSeenAt: string;
  current: boolean;
};

type Props = {
  email: string;
  envelope: VaultEnvelope;
  onClose: () => void;
  onSaveEnvelope: (envelope: VaultEnvelope) => Promise<VaultEnvelope>;
  onCurrentSessionRemoved: () => void;
};

async function requestJson<T>(url: string, options?: RequestInit): Promise<T> {
  const response = await fetch(url, options);
  const data = await response.json().catch(() => ({}));
  if (!response.ok) throw new Error(data.error ?? "请求失败");
  return data as T;
}

function sessionLabel(userAgent: string | null) {
  if (!userAgent) return "未知设备";
  const device = /iPhone/iu.test(userAgent) ? "iPhone" : /iPad/iu.test(userAgent) ? "iPad" : /Android/iu.test(userAgent) ? "Android" : /Macintosh/iu.test(userAgent) ? "Mac" : /Windows/iu.test(userAgent) ? "Windows" : "浏览器";
  const browser = /Edg\//iu.test(userAgent) ? "Edge" : /Firefox\//iu.test(userAgent) ? "Firefox" : /Chrome\//iu.test(userAgent) ? "Chrome" : /Safari\//iu.test(userAgent) ? "Safari" : "Web";
  return `${device} · ${browser}`;
}

export function SecurityCenter({ email, envelope, onClose, onSaveEnvelope, onCurrentSessionRemoved }: Props) {
  const [currentPassword, setCurrentPassword] = useState("");
  const [newPassword, setNewPassword] = useState("");
  const [confirmPassword, setConfirmPassword] = useState("");
  const [passwordsVisible, setPasswordsVisible] = useState(false);
  const [passwordBusy, setPasswordBusy] = useState(false);
  const [passwordMessage, setPasswordMessage] = useState("");
  const [recoveryPassword, setRecoveryPassword] = useState("");
  const [recoveryBusy, setRecoveryBusy] = useState(false);
  const [recoveryCode, setRecoveryCode] = useState("");
  const [recoverySaved, setRecoverySaved] = useState(false);
  const [recoveryMessage, setRecoveryMessage] = useState("");
  const [sessions, setSessions] = useState<SessionInfo[]>([]);
  const [sessionsBusy, setSessionsBusy] = useState(true);
  const [sessionsMessage, setSessionsMessage] = useState("");
  const [deleteBusy, setDeleteBusy] = useState(false);
  const [deleteMessage, setDeleteMessage] = useState("");
  const [deletePreviewUrl, setDeletePreviewUrl] = useState("");

  useEffect(() => {
    let active = true;
    void requestJson<{ sessions: SessionInfo[] }>("/api/account/sessions")
      .then((result) => { if (active) setSessions(result.sessions); })
      .catch((error: unknown) => { if (active) setSessionsMessage(error instanceof Error ? error.message : "无法读取登录设备"); })
      .finally(() => { if (active) setSessionsBusy(false); });
    return () => { active = false; };
  }, []);

  const savePassword = async (event: FormEvent) => {
    event.preventDefault();
    setPasswordMessage("");
    if (newPassword.length < 12) return setPasswordMessage("新主密码至少需要 12 个字符");
    if (newPassword !== confirmPassword) return setPasswordMessage("两次输入的新主密码不一致");
    if (currentPassword === newPassword) return setPasswordMessage("新主密码需要与当前主密码不同");
    setPasswordBusy(true);
    try {
      const next = await changeVaultPassword(envelope, currentPassword, newPassword);
      await onSaveEnvelope(next);
      setCurrentPassword("");
      setNewPassword("");
      setConfirmPassword("");
      setPasswordMessage("✓ 主密码已更新；旧主密码已失效");
    } catch {
      setPasswordMessage("当前主密码不正确，或同步失败");
    } finally {
      setPasswordBusy(false);
    }
  };

  const rotateRecovery = async (event: FormEvent) => {
    event.preventDefault();
    setRecoveryMessage("");
    setRecoveryBusy(true);
    try {
      const rotated = await rotateVaultRecoveryKey(envelope, recoveryPassword);
      await onSaveEnvelope(rotated.envelope);
      setRecoveryPassword("");
      setRecoveryCode(rotated.recoveryCode);
      setRecoverySaved(false);
    } catch {
      setRecoveryMessage("主密码不正确，或同步失败");
    } finally {
      setRecoveryBusy(false);
    }
  };

  const finishRecoveryRotation = () => {
    if (!recoverySaved) return;
    setRecoveryCode("");
    setRecoveryMessage("✓ 新恢复密钥已启用；旧恢复密钥已失效");
  };

  const removeSession = async (session: SessionInfo) => {
    setSessionsMessage("");
    try {
      const result = await requestJson<{ current: boolean }>("/api/account/sessions", {
        method: "DELETE",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ sessionId: session.id }),
      });
      if (result.current) return onCurrentSessionRemoved();
      setSessions((current) => current.filter((item) => item.id !== session.id));
    } catch (error) {
      setSessionsMessage(error instanceof Error ? error.message : "无法退出该设备");
    }
  };

  const requestDeletion = async () => {
    setDeleteBusy(true);
    setDeleteMessage("");
    try {
      const result = await requestJson<{ previewUrl?: string }>("/api/account/delete-request", { method: "POST" });
      setDeleteMessage(`确认邮件已发送至 ${email}`);
      setDeletePreviewUrl(result.previewUrl ?? "");
    } catch (error) {
      setDeleteMessage(error instanceof Error ? error.message : "无法发送确认邮件");
    } finally {
      setDeleteBusy(false);
    }
  };

  return <div className="modal-backdrop security-backdrop"><section className="security-center" role="dialog" aria-modal="true" aria-labelledby="security-title">
    <header><div><span className="eyebrow">账号与密钥</span><h2 id="security-title">安全中心</h2><p>{email}</p></div><button aria-label="关闭安全中心" disabled={Boolean(recoveryCode)} onClick={onClose}>×</button></header>
    <div className="security-content">
      <section className="security-section"><div className="security-section-heading"><div><span>01</span><h3>更改主密码</h3></div><p>只重新加密随机数据密钥，不会重新加密每个条目。</p></div>
        <form className="security-form" onSubmit={savePassword}>
          <label>当前主密码<input type={passwordsVisible ? "text" : "password"} required autoComplete="current-password" value={currentPassword} onChange={(event) => setCurrentPassword(event.target.value)} /></label>
          <label>新主密码<input type={passwordsVisible ? "text" : "password"} required minLength={12} autoComplete="new-password" value={newPassword} onChange={(event) => setNewPassword(event.target.value)} placeholder="至少 12 个字符" /></label>
          <label>确认新主密码<input type={passwordsVisible ? "text" : "password"} required minLength={12} autoComplete="new-password" value={confirmPassword} onChange={(event) => setConfirmPassword(event.target.value)} /></label>
          <label className="security-check"><input type="checkbox" checked={passwordsVisible} onChange={(event) => setPasswordsVisible(event.target.checked)} /> 显示并核对密码</label>
          {passwordMessage && <p className={passwordMessage.startsWith("✓") ? "security-success" : "form-error"}>{passwordMessage}</p>}
          <button className="primary-button" disabled={passwordBusy}>{passwordBusy ? "正在本地换密钥…" : "更新主密码"}</button>
        </form>
      </section>

      <section className="security-section"><div className="security-section-heading"><div><span>02</span><h3>轮换恢复密钥</h3></div><p>生成新恢复密钥并立即废止旧密钥。</p></div>
        {recoveryCode ? <div className="rotated-recovery"><p>新恢复密钥只显示这一次，请先保存：</p><code>{recoveryCode}</code><button onClick={() => void navigator.clipboard.writeText(recoveryCode)}>复制恢复密钥</button><label className="security-check"><input type="checkbox" checked={recoverySaved} onChange={(event) => setRecoverySaved(event.target.checked)} /> 我已将新恢复密钥保存到安全的位置</label><button className="primary-button" disabled={!recoverySaved} onClick={finishRecoveryRotation}>完成轮换</button></div> : <form className="security-form compact" onSubmit={rotateRecovery}>
          <label>当前主密码<input type="password" required autoComplete="current-password" value={recoveryPassword} onChange={(event) => setRecoveryPassword(event.target.value)} /></label>
          {recoveryMessage && <p className={recoveryMessage.startsWith("✓") ? "security-success" : "form-error"}>{recoveryMessage}</p>}
          <button disabled={recoveryBusy}>{recoveryBusy ? "正在生成…" : "生成并启用新恢复密钥"}</button>
        </form>}
      </section>

      <section className="security-section"><div className="security-section-heading"><div><span>03</span><h3>登录设备</h3></div><p>移除不认识或不再使用的浏览器会话。</p></div>
        <div className="session-list">{sessionsBusy ? <p className="security-muted">正在读取登录设备…</p> : sessions.map((session) => <div className="session-row" key={session.id}><div><strong>{sessionLabel(session.userAgent)} {session.current && <em>当前设备</em>}</strong><small>登录于 {new Date(session.createdAt).toLocaleString("zh-CN")}</small></div><button onClick={() => void removeSession(session)}>{session.current ? "退出" : "移除"}</button></div>)}{!sessionsBusy && sessions.length === 0 && <p className="security-muted">没有有效登录会话</p>}</div>
        {sessionsMessage && <p className="form-error">{sessionsMessage}</p>}
      </section>

      <section className="security-section danger-zone"><div className="security-section-heading"><div><span>04</span><h3>删除账号与数据</h3></div><p>通过邮箱链接二次确认后，永久删除账号、会话和云端密文。</p></div>
        <button disabled={deleteBusy} onClick={() => void requestDeletion()}>{deleteBusy ? "正在发送…" : "发送删除确认邮件"}</button>
        {deleteMessage && <p className="security-muted">{deleteMessage}</p>}
        {deletePreviewUrl && <a href={deletePreviewUrl}>本地开发：打开确认链接</a>}
      </section>
    </div>
  </section></div>;
}
