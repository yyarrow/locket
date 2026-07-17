"use client";

import { FormEvent, useCallback, useEffect, useMemo, useRef, useState } from "react";
import {
  createVault,
  encryptVaultData,
  isVaultEnvelope,
  recoverAndRekeyVault,
  unlockVault,
  type VaultEnvelope,
} from "@/lib/vault-crypto";

type Category = "login" | "card" | "note" | "wifi";
type VaultItem = {
  id: string;
  title: string;
  username: string;
  password: string;
  url: string;
  notes: string;
  category: Category;
  favorite: boolean;
  updatedAt: number;
};
type VaultData = { items: VaultItem[]; createdAt: number };
type Phase = "loading" | "account" | "email-sent" | "setup" | "recovery-save" | "locked" | "recover" | "open";
type AccountMode = "login" | "register" | "forgot";

const AUTO_LOCK_MS = 5 * 60 * 1000;
const categoryMeta: Record<Category, { label: string; glyph: string }> = {
  login: { label: "登录", glyph: "↗" },
  card: { label: "银行卡", glyph: "▤" },
  note: { label: "安全笔记", glyph: "≡" },
  wifi: { label: "Wi-Fi", glyph: "⌁" },
};

const emptyDraft = (): Omit<VaultItem, "id" | "updatedAt"> => ({
  title: "", username: "", password: "", url: "", notes: "", category: "login", favorite: false,
});

function makePassword(length = 20) {
  const sets = ["abcdefghijkmnopqrstuvwxyz", "ABCDEFGHJKLMNPQRSTUVWXYZ", "23456789", "!@#$%^&*_-+="];
  const pick = (set: string) => set[crypto.getRandomValues(new Uint32Array(1))[0] % set.length];
  const output = sets.map(pick);
  const all = sets.join("");
  while (output.length < length) output.push(pick(all));
  const random = crypto.getRandomValues(new Uint32Array(length));
  for (let index = output.length - 1; index > 0; index -= 1) {
    const swap = random[index] % (index + 1);
    [output[index], output[swap]] = [output[swap], output[index]];
  }
  return output.join("");
}

function toEnvelope(value: unknown): VaultEnvelope | null {
  if (!value || typeof value !== "object") return null;
  const source = value as Record<string, unknown>;
  const envelope = {
    formatVersion: source.formatVersion,
    ciphertext: source.ciphertext,
    iv: source.iv,
    wrappedKey: source.wrappedKey,
    wrapIv: source.wrapIv,
    recoveryWrappedKey: source.recoveryWrappedKey,
    recoveryWrapIv: source.recoveryWrapIv,
    kdfSalt: source.kdfSalt,
    kdfName: source.kdfName,
    kdfMemory: source.kdfMemory,
    kdfIterations: source.kdfIterations,
    kdfParallelism: source.kdfParallelism,
    itemCount: source.itemCount,
    revision: source.revision,
  };
  return isVaultEnvelope(envelope) ? envelope : null;
}

async function requestJson<T>(url: string, options?: RequestInit): Promise<T> {
  const response = await fetch(url, options);
  const data = await response.json().catch(() => ({}));
  if (!response.ok) throw new Error(data.error ?? "请求失败");
  return data as T;
}

export function VaultApp() {
  const [phase, setPhase] = useState<Phase>("loading");
  const [accountMode, setAccountMode] = useState<AccountMode>("login");
  const [accountEmail, setAccountEmail] = useState("");
  const [accountPassword, setAccountPassword] = useState("");
  const [accountPasswordConfirmation, setAccountPasswordConfirmation] = useState("");
  const [showAccountPassword, setShowAccountPassword] = useState(false);
  const [showAccountPasswordConfirmation, setShowAccountPasswordConfirmation] = useState(false);
  const [emailPreviewUrl, setEmailPreviewUrl] = useState("");
  const [masterPassword, setMasterPassword] = useState("");
  const [confirmPassword, setConfirmPassword] = useState("");
  const [recoveryCode, setRecoveryCode] = useState("");
  const [recoverySaved, setRecoverySaved] = useState(false);
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);
  const [data, setData] = useState<VaultData>({ items: [], createdAt: 0 });
  const [envelope, setEnvelope] = useState<VaultEnvelope | null>(null);
  const [query, setQuery] = useState("");
  const [category, setCategory] = useState<Category | "all" | "favorites">("all");
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [revealed, setRevealed] = useState(false);
  const [editorOpen, setEditorOpen] = useState(false);
  const [editingId, setEditingId] = useState<string | null>(null);
  const [draft, setDraft] = useState(emptyDraft());
  const [toast, setToast] = useState("");
  const [syncState, setSyncState] = useState<"saved" | "saving" | "error">("saved");
  const dataKeyRef = useRef<CryptoKey | null>(null);
  const pendingSetup = useRef<{ envelope: VaultEnvelope; dataKey: CryptoKey; data: VaultData } | null>(null);
  const lockTimer = useRef<ReturnType<typeof setTimeout> | null>(null);
  const importRef = useRef<HTMLInputElement>(null);

  const loadRemoteVault = useCallback(async () => {
    const response = await requestJson<{ vault: unknown }>("/api/vault");
    if (!response.vault) {
      setEnvelope(null);
      setPhase("setup");
      return;
    }
    const next = toEnvelope(response.vault);
    if (!next) throw new Error("云端保险库格式无法识别");
    setEnvelope(next);
    setPhase("locked");
  }, []);

  const boot = useCallback(async () => {
    setPhase("loading");
    setError("");
    try {
      const me = await requestJson<{ authenticated: boolean; email?: string }>("/api/auth/me");
      if (!me.authenticated) {
        setAccountEmail("");
        setPhase("account");
        return;
      }
      setAccountEmail(me.email ?? "");
      await loadRemoteVault();
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : "无法连接服务");
      setPhase("account");
    }
  }, [loadRemoteVault]);

  useEffect(() => { queueMicrotask(() => void boot()); }, [boot]);

  const lock = useCallback(() => {
    dataKeyRef.current = null;
    setData({ items: [], createdAt: 0 });
    setSelectedId(null);
    setMasterPassword("");
    setConfirmPassword("");
    setRecoveryCode("");
    setRevealed(false);
    setEditorOpen(false);
    setPhase("locked");
  }, []);

  useEffect(() => {
    if (phase !== "open") return;
    const reset = () => {
      if (lockTimer.current) clearTimeout(lockTimer.current);
      lockTimer.current = setTimeout(lock, AUTO_LOCK_MS);
    };
    const events: (keyof WindowEventMap)[] = ["pointerdown", "keydown", "touchstart"];
    events.forEach((event) => window.addEventListener(event, reset, { passive: true }));
    reset();
    return () => {
      if (lockTimer.current) clearTimeout(lockTimer.current);
      events.forEach((event) => window.removeEventListener(event, reset));
    };
  }, [phase, lock]);

  useEffect(() => {
    if (!toast) return;
    const timer = setTimeout(() => setToast(""), 2600);
    return () => clearTimeout(timer);
  }, [toast]);

  const putEnvelope = async (next: VaultEnvelope) => {
    const response = await requestJson<{ revision: number }>("/api/vault", {
      method: "PUT",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(next),
    });
    return { ...next, revision: response.revision };
  };

  const saveData = useCallback(async (nextData: VaultData) => {
    if (!dataKeyRef.current || !envelope) return;
    setSyncState("saving");
    try {
      const encrypted = await encryptVaultData(nextData, dataKeyRef.current, envelope);
      const saved = await putEnvelope(encrypted);
      setEnvelope(saved);
      setData(nextData);
      setSyncState("saved");
    } catch (cause) {
      setSyncState("error");
      setToast(cause instanceof Error ? cause.message : "同步失败");
      throw cause;
    }
  }, [envelope]);

  const handleAccount = async (event: FormEvent) => {
    event.preventDefault();
    setError("");
    if (accountMode === "register" && accountPassword !== accountPasswordConfirmation) {
      setError("两次输入的登录密码不一致。");
      return;
    }
    setBusy(true);
    try {
      if (accountMode === "forgot") {
        const response = await requestJson<{ previewUrl?: string }>("/api/auth/forgot", {
          method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ email: accountEmail }),
        });
        setEmailPreviewUrl(response.previewUrl ?? "");
        setPhase("email-sent");
      } else if (accountMode === "register") {
        const response = await requestJson<{ previewUrl?: string }>("/api/auth/register", {
          method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ email: accountEmail, password: accountPassword }),
        });
        setAccountPassword("");
        setAccountPasswordConfirmation("");
        setShowAccountPassword(false);
        setShowAccountPasswordConfirmation(false);
        setEmailPreviewUrl(response.previewUrl ?? "");
        setPhase("email-sent");
      } else {
        await requestJson("/api/auth/login", {
          method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ email: accountEmail, password: accountPassword }),
        });
        setAccountPassword("");
        setAccountPasswordConfirmation("");
        await boot();
      }
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : "操作失败");
    } finally { setBusy(false); }
  };

  const handleSetup = async (event: FormEvent) => {
    event.preventDefault();
    setError("");
    if (masterPassword.length < 12) return setError("主密码至少需要 12 个字符。");
    if (masterPassword !== confirmPassword) return setError("两次输入的主密码不一致。");
    setBusy(true);
    try {
      const initial: VaultData = { items: [], createdAt: Date.now() };
      const created = await createVault(masterPassword, initial);
      pendingSetup.current = { envelope: created.envelope, dataKey: created.dataKey, data: initial };
      setRecoveryCode(created.recoveryCode);
      setMasterPassword("");
      setConfirmPassword("");
      setRecoverySaved(false);
      setPhase("recovery-save");
    } catch { setError("创建加密保险库失败，请重试。"); }
    finally { setBusy(false); }
  };

  const finishSetup = async () => {
    if (!recoverySaved || !pendingSetup.current) return;
    setBusy(true);
    setError("");
    try {
      const pending = pendingSetup.current;
      const saved = await putEnvelope(pending.envelope);
      dataKeyRef.current = pending.dataKey;
      setEnvelope(saved);
      setData(pending.data);
      pendingSetup.current = null;
      setRecoveryCode("");
      setPhase("open");
    } catch (cause) { setError(cause instanceof Error ? cause.message : "保存失败"); }
    finally { setBusy(false); }
  };

  const handleUnlock = async (event: FormEvent) => {
    event.preventDefault();
    if (!envelope) return;
    setBusy(true);
    setError("");
    try {
      const unlocked = await unlockVault<VaultData>(envelope, masterPassword);
      dataKeyRef.current = unlocked.dataKey;
      setData(unlocked.data);
      setSelectedId(unlocked.data.items[0]?.id ?? null);
      setMasterPassword("");
      setPhase("open");
    } catch { setError("主密码不正确，或保险库已损坏。"); }
    finally { setBusy(false); }
  };

  const handleRecovery = async (event: FormEvent) => {
    event.preventDefault();
    if (!envelope) return;
    setError("");
    if (masterPassword.length < 12 || masterPassword !== confirmPassword) return setError("请设置两次一致、至少 12 位的新主密码。");
    setBusy(true);
    try {
      const recovered = await recoverAndRekeyVault<VaultData>(envelope, recoveryCode, masterPassword);
      const saved = await putEnvelope(recovered.envelope);
      dataKeyRef.current = recovered.dataKey;
      setEnvelope(saved);
      setData(recovered.data);
      setRecoveryCode(""); setMasterPassword(""); setConfirmPassword(""); setPhase("open");
      setToast("保险库已恢复，主密码已更新");
    } catch { setError("恢复密钥无效，或保险库已损坏。"); }
    finally { setBusy(false); }
  };

  const logout = async () => {
    await requestJson("/api/auth/logout", { method: "POST" }).catch(() => null);
    dataKeyRef.current = null; setEnvelope(null); setData({ items: [], createdAt: 0 }); setAccountPassword("");
    setAccountMode("login"); setPhase("account");
  };

  const filtered = useMemo(() => {
    const normalized = query.trim().toLowerCase();
    return [...data.items].filter((item) => {
      const categoryMatch = category === "all" || (category === "favorites" ? item.favorite : item.category === category);
      const textMatch = !normalized || [item.title, item.username, item.url, item.notes].some((value) => value.toLowerCase().includes(normalized));
      return categoryMatch && textMatch;
    }).sort((a, b) => Number(b.favorite) - Number(a.favorite) || b.updatedAt - a.updatedAt);
  }, [data.items, category, query]);

  const selected = data.items.find((item) => item.id === selectedId) ?? filtered[0] ?? null;
  const openNew = () => {
    if (data.items.length >= 500) return setToast("免费版最多保存 500 个条目");
    setEditingId(null); setDraft({ ...emptyDraft(), password: makePassword() }); setEditorOpen(true);
  };
  const openEdit = (item: VaultItem) => {
    setEditingId(item.id);
    setDraft({ title: item.title, username: item.username, password: item.password, url: item.url, notes: item.notes, category: item.category, favorite: item.favorite });
    setEditorOpen(true);
  };
  const saveItem = async (event: FormEvent) => {
    event.preventDefault();
    if (!draft.title.trim()) return;
    const item: VaultItem = { ...draft, title: draft.title.trim(), id: editingId ?? crypto.randomUUID(), updatedAt: Date.now() };
    const items = editingId ? data.items.map((current) => current.id === editingId ? item : current) : [item, ...data.items];
    await saveData({ ...data, items }); setSelectedId(item.id); setEditorOpen(false); setToast(editingId ? "条目已更新并同步" : "条目已加密同步");
  };
  const deleteItem = async (item: VaultItem) => {
    if (!window.confirm(`删除“${item.title}”？此操作无法撤销。`)) return;
    const items = data.items.filter((current) => current.id !== item.id);
    await saveData({ ...data, items }); setSelectedId(items[0]?.id ?? null); setToast("条目已删除");
  };
  const toggleFavorite = async (item: VaultItem) => {
    const items = data.items.map((current) => current.id === item.id ? { ...current, favorite: !current.favorite, updatedAt: Date.now() } : current);
    await saveData({ ...data, items });
  };
  const copy = async (value: string, label: string) => {
    await navigator.clipboard.writeText(value); setToast(`${label}已复制，30 秒后尝试清空剪贴板`);
    setTimeout(async () => { try { if ((await navigator.clipboard.readText()) === value) await navigator.clipboard.writeText(""); } catch { /* permission expired */ } }, 30_000);
  };
  const exportVault = () => {
    if (!envelope) return;
    const blob = new Blob([JSON.stringify({ type: "locket-encrypted-backup", exportedAt: new Date().toISOString(), vault: envelope }, null, 2)], { type: "application/json" });
    const url = URL.createObjectURL(blob); const anchor = document.createElement("a"); anchor.href = url;
    anchor.download = `locket-backup-${new Date().toISOString().slice(0, 10)}.json`; anchor.click(); URL.revokeObjectURL(url); setToast("加密备份已导出");
  };
  const importVault = async (file: File) => {
    try {
      const parsed = JSON.parse(await file.text()) as { vault?: unknown };
      const imported = toEnvelope(parsed.vault ?? parsed);
      if (!imported || !envelope) throw new Error("文件格式不正确");
      const saved = await putEnvelope({ ...imported, revision: envelope.revision });
      setEnvelope(saved); setToast("备份已恢复，请使用备份对应的主密码解锁"); lock();
    } catch (cause) { setToast(cause instanceof Error ? cause.message : "无法导入备份"); }
  };

  if (phase === "loading") return <main className="auth-shell"><div className="auth-card loading-card" role="status"><div className="brand-mark">L</div><p>正在安全连接…</p></div></main>;

  if (phase === "account" || phase === "email-sent") {
    return <main className="auth-shell"><section className="auth-card account-card">
      <div className="brand-row"><div className="brand-mark">L</div><span>Locket</span></div>
      {phase === "email-sent" ? <div className="email-sent"><span className="success-mark">✓</span><h1>检查你的邮箱</h1><p>邮件里的链接会在 1 小时后失效。账号密码重置不会重置保险库主密码。</p>{emailPreviewUrl && <a href={emailPreviewUrl}>本地开发：打开邮件链接</a>}<button onClick={() => { setPhase("account"); setAccountMode("login"); }}>返回登录</button></div> : <>
        <div className="auth-copy"><span className="eyebrow">免费公测 · 端到端加密</span><h1>{accountMode === "login" ? "登录 Locket" : accountMode === "register" ? "创建免费账号" : "找回登录密码"}</h1><p>{accountMode === "forgot" ? "我们会发送一次性重置链接。你的保险库主密码不会改变。" : "账号用于同步密文；主密码只在你的浏览器里解密保险库。"}</p></div>
        {accountMode !== "forgot" && <div className="auth-tabs"><button className={accountMode === "login" ? "active" : ""} onClick={() => { setAccountMode("login"); setAccountPasswordConfirmation(""); setError(""); }}>登录</button><button className={accountMode === "register" ? "active" : ""} onClick={() => { setAccountMode("register"); setError(""); }}>注册</button></div>}
        <form onSubmit={handleAccount} className="auth-form">
          <label>邮箱<input type="email" required autoComplete="email" value={accountEmail} onChange={(event) => setAccountEmail(event.target.value)} placeholder="you@example.com" /></label>
          {accountMode !== "forgot" && <label>登录密码<div className="auth-password-input"><input type={showAccountPassword ? "text" : "password"} required minLength={12} maxLength={256} autoComplete={accountMode === "register" ? "new-password" : "current-password"} value={accountPassword} onChange={(event) => setAccountPassword(event.target.value)} placeholder="至少 12 个字符" /><button type="button" aria-label={showAccountPassword ? "隐藏登录密码" : "显示登录密码"} aria-pressed={showAccountPassword} onClick={() => setShowAccountPassword((value) => !value)}>{showAccountPassword ? "隐藏" : "显示"}</button></div></label>}
          {accountMode === "register" && <label>确认登录密码<div className="auth-password-input"><input type={showAccountPasswordConfirmation ? "text" : "password"} required minLength={12} maxLength={256} autoComplete="new-password" value={accountPasswordConfirmation} onChange={(event) => setAccountPasswordConfirmation(event.target.value)} placeholder="再次输入登录密码" /><button type="button" aria-label={showAccountPasswordConfirmation ? "隐藏确认密码" : "显示确认密码"} aria-pressed={showAccountPasswordConfirmation} onClick={() => setShowAccountPasswordConfirmation((value) => !value)}>{showAccountPasswordConfirmation ? "隐藏" : "显示"}</button></div></label>}
          {error && <p className="form-error">{error}</p>}
          <button className="primary-button" disabled={busy}>{busy ? "处理中…" : accountMode === "login" ? "登录" : accountMode === "register" ? "创建账号" : "发送重置邮件"}</button>
        </form>
        <button className="text-button" onClick={() => { setAccountMode(accountMode === "forgot" ? "login" : "forgot"); setError(""); }}>{accountMode === "forgot" ? "返回登录" : "忘记登录密码？"}</button>
      </>}
    </section><p className="auth-footer">账号密码 ≠ 保险库主密码 · 服务端只保存密文</p></main>;
  }

  if (phase === "setup" || phase === "locked" || phase === "recover") {
    const setup = phase === "setup"; const recovering = phase === "recover";
    return <main className="auth-shell"><section className="auth-card">
      <div className="brand-row"><div className="brand-mark">L</div><span>Locket</span><span className="account-email">{accountEmail}</span></div>
      <div className="auth-copy"><span className="eyebrow">端到端加密保险库</span><h1>{setup ? "创建主密码" : recovering ? "使用恢复密钥" : "解锁保险库"}</h1><p>{setup ? "主密码不会上传，也无法通过邮箱找回。下一步会生成恢复密钥。" : recovering ? "输入恢复密钥并设置新的主密码。" : "密文已从云端取回，解密只在此设备进行。"}</p></div>
      <form onSubmit={setup ? handleSetup : recovering ? handleRecovery : handleUnlock} className="auth-form">
        {recovering && <label>恢复密钥<input value={recoveryCode} onChange={(event) => setRecoveryCode(event.target.value)} placeholder="LK1-…" autoComplete="off" /></label>}
        <label>{recovering ? "新主密码" : "主密码"}<input type="password" autoFocus autoComplete="off" value={masterPassword} onChange={(event) => setMasterPassword(event.target.value)} placeholder={setup || recovering ? "至少 12 个字符" : "输入主密码"} /></label>
        {(setup || recovering) && <label>确认主密码<input type="password" autoComplete="off" value={confirmPassword} onChange={(event) => setConfirmPassword(event.target.value)} placeholder="再次输入主密码" /></label>}
        {error && <p className="form-error">{error}</p>}
        <button className="primary-button" disabled={busy || !masterPassword}>{busy ? "处理中…" : setup ? "生成恢复密钥" : recovering ? "恢复并更新主密码" : "解锁保险库"}</button>
      </form>
      {!setup && <button className="text-button" onClick={() => { setPhase(recovering ? "locked" : "recover"); setError(""); setMasterPassword(""); setConfirmPassword(""); }}>{recovering ? "返回主密码解锁" : "忘记主密码？使用恢复密钥"}</button>}
      <div className="security-note"><span>◆</span><p><strong>双层身份保护</strong><br />登录密码保护账号，主密码保护保险库内容。</p></div>
      <button className="auth-logout" onClick={() => void logout()}>退出账号</button>
    </section><p className="auth-footer">Argon2id · AES-256-GCM · 零知识密文同步</p></main>;
  }

  if (phase === "recovery-save") {
    return <main className="auth-shell"><section className="auth-card recovery-card">
      <div className="brand-row"><div className="brand-mark">L</div><span>Locket</span></div>
      <div className="auth-copy"><span className="eyebrow">仅显示一次</span><h1>保存恢复密钥</h1><p>忘记主密码时，这是恢复保险库的唯一方式。我们不会保存它。</p></div>
      <code className="recovery-code">{recoveryCode}</code>
      <button className="copy-recovery" onClick={() => void copy(recoveryCode, "恢复密钥")}>复制恢复密钥</button>
      <label className="recovery-confirm"><input type="checkbox" checked={recoverySaved} onChange={(event) => setRecoverySaved(event.target.checked)} /> 我已将恢复密钥保存到安全的位置</label>
      {error && <p className="form-error">{error}</p>}
      <button className="primary-button" disabled={!recoverySaved || busy} onClick={() => void finishSetup()}>{busy ? "正在加密同步…" : "创建保险库"}</button>
    </section><p className="auth-footer">关闭页面前请先保存恢复密钥</p></main>;
  }

  return <main className="app-shell">
    <aside className="sidebar">
      <div className="brand-row sidebar-brand"><div className="brand-mark">L</div><span>Locket</span></div>
      <button className="new-button" onClick={openNew}><span>＋</span> 新建条目</button>
      <nav aria-label="保险库分类"><p className="nav-label">保险库</p>
        <button className={category === "all" ? "active" : ""} onClick={() => setCategory("all")}><span className="nav-icon">◇</span> 所有条目 <b>{data.items.length}</b></button>
        <button className={category === "favorites" ? "active" : ""} onClick={() => setCategory("favorites")}><span className="nav-icon">☆</span> 收藏 <b>{data.items.filter((item) => item.favorite).length}</b></button>
        <p className="nav-label categories-label">分类</p>
        {(Object.keys(categoryMeta) as Category[]).map((key) => <button key={key} className={category === key ? "active" : ""} onClick={() => setCategory(key)}><span className="nav-icon">{categoryMeta[key].glyph}</span> {categoryMeta[key].label}<b>{data.items.filter((item) => item.category === key).length}</b></button>)}
      </nav>
      <div className="sidebar-bottom">
        <button onClick={exportVault}><span>↓</span> 导出加密备份</button><button onClick={() => importRef.current?.click()}><span>↑</span> 导入备份</button>
        <input ref={importRef} hidden type="file" accept="application/json,.json" onChange={(event) => { const file = event.target.files?.[0]; if (file) void importVault(file); event.currentTarget.value = ""; }} />
        <button onClick={lock}><span>⌁</span> 锁定保险库</button><button onClick={() => void logout()}><span>×</span> 退出账号</button>
        <div className={`local-status ${syncState}`}><i /> {syncState === "saving" ? "正在加密同步" : syncState === "error" ? "同步失败" : "密文已安全同步"}</div>
      </div>
    </aside>
    <section className="list-panel">
      <div className="panel-header"><div><span className="eyebrow">{accountEmail}</span><h1>{category === "all" ? "所有条目" : category === "favorites" ? "收藏" : categoryMeta[category].label}</h1></div><button className="mobile-new" onClick={openNew}>＋</button></div>
      <label className="search-box"><span>⌕</span><input value={query} onChange={(event) => setQuery(event.target.value)} placeholder="搜索保险库" /><kbd>⌘ K</kbd></label>
      <div className="item-count">{filtered.length} / 500 个条目</div>
      <div className="item-list">{filtered.length === 0 ? <div className="empty-state"><div>＋</div><h2>{query ? "没有匹配的条目" : "保险库还是空的"}</h2><p>{query ? "试试其他关键词。" : "保存你的第一个登录信息或安全笔记。"}</p>{!query && <button onClick={openNew}>新建条目</button>}</div> : filtered.map((item) => <button className={`item-row ${selected?.id === item.id ? "selected" : ""}`} key={item.id} onClick={() => { setSelectedId(item.id); setRevealed(false); }}><span className={`item-avatar ${item.category}`}>{item.title.slice(0, 1).toUpperCase()}</span><span className="item-text"><strong>{item.title}</strong><small>{item.username || categoryMeta[item.category].label}</small></span>{item.favorite && <span className="favorite-star">★</span>}<span className="chevron">›</span></button>)}</div>
    </section>
    <section className="detail-panel">{selected ? <><header className="detail-header"><div className={`detail-avatar ${selected.category}`}>{selected.title.slice(0, 1).toUpperCase()}</div><div><h2>{selected.title}</h2><p>{categoryMeta[selected.category].label}</p></div><div className="detail-actions"><button aria-label={selected.favorite ? "取消收藏" : "收藏"} onClick={() => void toggleFavorite(selected)}>{selected.favorite ? "★" : "☆"}</button><button onClick={() => openEdit(selected)}>编辑</button><button className="danger-action" aria-label="删除" onClick={() => void deleteItem(selected)}>•••</button></div></header>
      <div className="detail-body"><div className="field-group"><p className="field-label">登录信息</p><div className="value-row"><span><small>用户名</small><strong>{selected.username || "—"}</strong></span>{selected.username && <button onClick={() => void copy(selected.username, "用户名")}>复制</button>}</div><div className="value-row password-row"><span><small>密码</small><strong>{revealed ? selected.password : "••••••••••••••"}</strong></span><div><button onClick={() => setRevealed((value) => !value)}>{revealed ? "隐藏" : "显示"}</button>{selected.password && <button onClick={() => void copy(selected.password, "密码")}>复制</button>}</div></div></div>
        {selected.url && <div className="field-group"><p className="field-label">网站</p><div className="value-row"><a href={selected.url.startsWith("http") ? selected.url : `https://${selected.url}`} target="_blank" rel="noreferrer">{selected.url} <span>↗</span></a><button onClick={() => void copy(selected.url, "网址")}>复制</button></div></div>}{selected.notes && <div className="field-group"><p className="field-label">备注</p><p className="notes-value">{selected.notes}</p></div>}<p className="updated-time">上次更新于 {new Date(selected.updatedAt).toLocaleString("zh-CN")}</p></div>
    </> : <div className="detail-empty"><div className="brand-mark">L</div><h2>选择一个条目</h2><p>查看、复制或编辑保存在保险库中的信息。</p></div>}</section>
    {editorOpen && <div className="modal-backdrop" role="presentation" onMouseDown={() => setEditorOpen(false)}><section className="editor" role="dialog" aria-modal="true" aria-labelledby="editor-title" onMouseDown={(event) => event.stopPropagation()}><header><div><span className="eyebrow">端到端加密条目</span><h2 id="editor-title">{editingId ? "编辑条目" : "新建条目"}</h2></div><button aria-label="关闭" onClick={() => setEditorOpen(false)}>×</button></header><form onSubmit={saveItem}>
      <div className="category-picker">{(Object.keys(categoryMeta) as Category[]).map((key) => <button type="button" key={key} className={draft.category === key ? "active" : ""} onClick={() => setDraft({ ...draft, category: key })}><span>{categoryMeta[key].glyph}</span>{categoryMeta[key].label}</button>)}</div>
      <label>名称<input autoFocus required value={draft.title} onChange={(event) => setDraft({ ...draft, title: event.target.value })} placeholder="例如：GitHub" /></label><label>用户名<input value={draft.username} onChange={(event) => setDraft({ ...draft, username: event.target.value })} placeholder="邮箱或用户名" /></label><label>密码<div className="password-input"><input value={draft.password} onChange={(event) => setDraft({ ...draft, password: event.target.value })} /><button type="button" onClick={() => setDraft({ ...draft, password: makePassword() })}>重新生成</button></div></label><label>网址<input value={draft.url} onChange={(event) => setDraft({ ...draft, url: event.target.value })} placeholder="https://example.com" /></label><label>备注<textarea value={draft.notes} onChange={(event) => setDraft({ ...draft, notes: event.target.value })} placeholder="可选的安全备注" /></label><label className="favorite-check"><input type="checkbox" checked={draft.favorite} onChange={(event) => setDraft({ ...draft, favorite: event.target.checked })} /> 添加到收藏</label><footer><button type="button" onClick={() => setEditorOpen(false)}>取消</button><button className="primary-button">保存并同步</button></footer>
    </form></section></div>}
    {toast && <div className="toast" role="status">✓ {toast}</div>}
  </main>;
}
