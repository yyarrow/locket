"use client";

import { FormEvent, useCallback, useEffect, useMemo, useRef, useState } from "react";

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

type StoredVault = {
  version: 1;
  salt: string;
  iv: string;
  ciphertext: string;
  iterations: number;
};

const DB_NAME = "locket-vault";
const STORE_NAME = "encrypted-records";
const VAULT_KEY = "primary";
const ITERATIONS = 310_000;
const AUTO_LOCK_MS = 5 * 60 * 1000;

const categoryMeta: Record<Category, { label: string; glyph: string }> = {
  login: { label: "登录", glyph: "↗" },
  card: { label: "银行卡", glyph: "▤" },
  note: { label: "安全笔记", glyph: "≡" },
  wifi: { label: "Wi-Fi", glyph: "⌁" },
};

const encoder = new TextEncoder();
const decoder = new TextDecoder();

function bytesToBase64(bytes: Uint8Array) {
  let binary = "";
  bytes.forEach((byte) => (binary += String.fromCharCode(byte)));
  return btoa(binary);
}

function base64ToBytes(value: string) {
  const binary = atob(value);
  return Uint8Array.from(binary, (char) => char.charCodeAt(0));
}

function openDatabase(): Promise<IDBDatabase> {
  return new Promise((resolve, reject) => {
    const request = indexedDB.open(DB_NAME, 1);
    request.onupgradeneeded = () => {
      if (!request.result.objectStoreNames.contains(STORE_NAME)) {
        request.result.createObjectStore(STORE_NAME);
      }
    };
    request.onsuccess = () => resolve(request.result);
    request.onerror = () => reject(request.error);
  });
}

async function readStoredVault(): Promise<StoredVault | undefined> {
  const db = await openDatabase();
  return new Promise((resolve, reject) => {
    const transaction = db.transaction(STORE_NAME, "readonly");
    const request = transaction.objectStore(STORE_NAME).get(VAULT_KEY);
    request.onsuccess = () => resolve(request.result as StoredVault | undefined);
    request.onerror = () => reject(request.error);
    transaction.oncomplete = () => db.close();
  });
}

async function writeStoredVault(vault: StoredVault) {
  const db = await openDatabase();
  return new Promise<void>((resolve, reject) => {
    const transaction = db.transaction(STORE_NAME, "readwrite");
    transaction.objectStore(STORE_NAME).put(vault, VAULT_KEY);
    transaction.oncomplete = () => {
      db.close();
      resolve();
    };
    transaction.onerror = () => reject(transaction.error);
  });
}

async function deriveKey(password: string, salt: Uint8Array, iterations: number) {
  const material = await crypto.subtle.importKey("raw", encoder.encode(password), "PBKDF2", false, ["deriveKey"]);
  return crypto.subtle.deriveKey(
    { name: "PBKDF2", hash: "SHA-256", salt: salt as BufferSource, iterations },
    material,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"],
  );
}

async function encryptVault(data: VaultData, key: CryptoKey, salt: Uint8Array) {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const encrypted = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv },
    key,
    encoder.encode(JSON.stringify(data)),
  );
  return {
    version: 1 as const,
    salt: bytesToBase64(salt),
    iv: bytesToBase64(iv),
    ciphertext: bytesToBase64(new Uint8Array(encrypted)),
    iterations: ITERATIONS,
  };
}

async function decryptVault(vault: StoredVault, password: string) {
  const salt = base64ToBytes(vault.salt);
  const key = await deriveKey(password, salt, vault.iterations);
  const clear = await crypto.subtle.decrypt(
    { name: "AES-GCM", iv: base64ToBytes(vault.iv) },
    key,
    base64ToBytes(vault.ciphertext),
  );
  return { data: JSON.parse(decoder.decode(clear)) as VaultData, key, salt };
}

function makePassword(length = 20) {
  const lower = "abcdefghijkmnopqrstuvwxyz";
  const upper = "ABCDEFGHJKLMNPQRSTUVWXYZ";
  const numbers = "23456789";
  const symbols = "!@#$%^&*_-+=";
  const all = lower + upper + numbers + symbols;
  const random = crypto.getRandomValues(new Uint32Array(length));
  const required = [lower, upper, numbers, symbols].map((set, index) => {
    const n = crypto.getRandomValues(new Uint32Array(1))[0];
    return { char: set[n % set.length], at: random[index] % length };
  });
  const output = Array.from(random, (n) => all[n % all.length]);
  required.forEach(({ char, at }) => (output[at] = char));
  return output.join("");
}

function isStoredVault(value: unknown): value is StoredVault {
  if (!value || typeof value !== "object") return false;
  const candidate = value as Partial<StoredVault>;
  return candidate.version === 1 && typeof candidate.salt === "string" &&
    typeof candidate.iv === "string" && typeof candidate.ciphertext === "string" &&
    typeof candidate.iterations === "number";
}

const emptyDraft = (): Omit<VaultItem, "id" | "updatedAt"> => ({
  title: "", username: "", password: "", url: "", notes: "", category: "login", favorite: false,
});

export function VaultApp() {
  const [phase, setPhase] = useState<"loading" | "setup" | "locked" | "open">("loading");
  const [data, setData] = useState<VaultData>({ items: [], createdAt: Date.now() });
  const [password, setPassword] = useState("");
  const [confirmPassword, setConfirmPassword] = useState("");
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);
  const [query, setQuery] = useState("");
  const [category, setCategory] = useState<Category | "all" | "favorites">("all");
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [revealed, setRevealed] = useState(false);
  const [editorOpen, setEditorOpen] = useState(false);
  const [editingId, setEditingId] = useState<string | null>(null);
  const [draft, setDraft] = useState(emptyDraft());
  const [toast, setToast] = useState("");
  const keyRef = useRef<CryptoKey | null>(null);
  const saltRef = useRef<Uint8Array | null>(null);
  const lockTimer = useRef<ReturnType<typeof setTimeout> | null>(null);
  const importRef = useRef<HTMLInputElement>(null);

  useEffect(() => {
    readStoredVault().then((vault) => setPhase(vault ? "locked" : "setup")).catch(() => {
      setError("无法访问本地存储，请检查浏览器隐私设置。");
      setPhase("setup");
    });
  }, []);

  const lock = useCallback(() => {
    keyRef.current = null;
    saltRef.current = null;
    setData({ items: [], createdAt: 0 });
    setSelectedId(null);
    setPassword("");
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
    const timer = setTimeout(() => setToast(""), 2200);
    return () => clearTimeout(timer);
  }, [toast]);

  const saveData = useCallback(async (next: VaultData) => {
    if (!keyRef.current || !saltRef.current) return;
    await writeStoredVault(await encryptVault(next, keyRef.current, saltRef.current));
    setData(next);
  }, []);

  const handleSetup = async (event: FormEvent) => {
    event.preventDefault();
    setError("");
    if (password.length < 12) return setError("主密码至少需要 12 个字符。");
    if (password !== confirmPassword) return setError("两次输入的密码不一致。");
    setBusy(true);
    try {
      const salt = crypto.getRandomValues(new Uint8Array(16));
      const key = await deriveKey(password, salt, ITERATIONS);
      const initial: VaultData = { items: [], createdAt: Date.now() };
      await writeStoredVault(await encryptVault(initial, key, salt));
      keyRef.current = key;
      saltRef.current = salt;
      setData(initial);
      setPassword("");
      setConfirmPassword("");
      setPhase("open");
    } catch {
      setError("创建保险库失败，请重试。");
    } finally {
      setBusy(false);
    }
  };

  const handleUnlock = async (event: FormEvent) => {
    event.preventDefault();
    setBusy(true);
    setError("");
    try {
      const stored = await readStoredVault();
      if (!stored) { setPhase("setup"); return; }
      const unlocked = await decryptVault(stored, password);
      keyRef.current = unlocked.key;
      saltRef.current = unlocked.salt;
      setData(unlocked.data);
      setSelectedId(unlocked.data.items[0]?.id ?? null);
      setPassword("");
      setPhase("open");
    } catch {
      setError("主密码不正确，或保险库已损坏。");
    } finally {
      setBusy(false);
    }
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
  const openNew = () => { setEditingId(null); setDraft({ ...emptyDraft(), password: makePassword() }); setEditorOpen(true); };
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
    await saveData({ ...data, items });
    setSelectedId(item.id);
    setEditorOpen(false);
    setToast(editingId ? "条目已更新" : "条目已保存");
  };
  const deleteItem = async (item: VaultItem) => {
    if (!window.confirm(`删除“${item.title}”？此操作无法撤销。`)) return;
    const items = data.items.filter((current) => current.id !== item.id);
    await saveData({ ...data, items });
    setSelectedId(items[0]?.id ?? null);
    setToast("条目已删除");
  };
  const toggleFavorite = async (item: VaultItem) => {
    const items = data.items.map((current) => current.id === item.id ? { ...current, favorite: !current.favorite, updatedAt: Date.now() } : current);
    await saveData({ ...data, items });
  };
  const copy = async (value: string, label: string) => {
    await navigator.clipboard.writeText(value);
    setToast(`${label}已复制，30 秒后尝试清空剪贴板`);
    setTimeout(async () => {
      try { if ((await navigator.clipboard.readText()) === value) await navigator.clipboard.writeText(""); } catch { /* permission expired */ }
    }, 30_000);
  };
  const exportVault = async () => {
    const stored = await readStoredVault();
    if (!stored) return;
    const url = URL.createObjectURL(new Blob([JSON.stringify(stored, null, 2)], { type: "application/json" }));
    const anchor = document.createElement("a");
    anchor.href = url;
    anchor.download = `locket-backup-${new Date().toISOString().slice(0, 10)}.json`;
    anchor.click();
    URL.revokeObjectURL(url);
    setToast("加密备份已导出");
  };
  const importVault = async (file: File) => {
    try {
      const parsed = JSON.parse(await file.text()) as unknown;
      if (!isStoredVault(parsed)) throw new Error("Invalid vault");
      await writeStoredVault(parsed);
      setToast("备份已导入，请用对应主密码解锁");
      lock();
    } catch { setToast("无法导入：文件格式不正确"); }
  };

  if (phase === "loading") return <main className="auth-shell"><div className="auth-card loading-card" role="status"><div className="brand-mark">L</div><p>正在打开本地保险库…</p></div></main>;

  if (phase === "setup" || phase === "locked") {
    const setup = phase === "setup";
    return (
      <main className="auth-shell">
        <section className="auth-card">
          <div className="brand-row"><div className="brand-mark">L</div><span>Locket</span></div>
          <div className="auth-copy"><span className="eyebrow">本地加密保险库</span><h1>{setup ? "创建你的保险库" : "欢迎回来"}</h1><p>{setup ? "所有数据都在此设备上加密。主密码不会被保存或上传。" : "输入主密码，在此设备上解密你的保险库。"}</p></div>
          <form onSubmit={setup ? handleSetup : handleUnlock} className="auth-form">
            <label>主密码<input type="password" autoFocus autoComplete={setup ? "new-password" : "current-password"} value={password} onChange={(event) => setPassword(event.target.value)} placeholder={setup ? "至少 12 个字符" : "输入主密码"} /></label>
            {setup && <label>确认主密码<input type="password" autoComplete="new-password" value={confirmPassword} onChange={(event) => setConfirmPassword(event.target.value)} placeholder="再次输入主密码" /></label>}
            {error && <p className="form-error">{error}</p>}
            <button className="primary-button" disabled={busy || !password}>{busy ? "处理中…" : setup ? "创建并解锁" : "解锁保险库"}</button>
          </form>
          <div className="security-note"><span>◆</span><p><strong>请妥善保管主密码</strong><br />我们无法重置或找回它。</p></div>
        </section>
        <p className="auth-footer">AES-256-GCM · PBKDF2-SHA256 · 零云端</p>
      </main>
    );
  }

  return (
    <main className="app-shell">
      <aside className="sidebar">
        <div className="brand-row sidebar-brand"><div className="brand-mark">L</div><span>Locket</span></div>
        <button className="new-button" onClick={openNew}><span>＋</span> 新建条目</button>
        <nav aria-label="保险库分类">
          <p className="nav-label">保险库</p>
          <button className={category === "all" ? "active" : ""} onClick={() => setCategory("all")}><span className="nav-icon">◇</span> 所有条目 <b>{data.items.length}</b></button>
          <button className={category === "favorites" ? "active" : ""} onClick={() => setCategory("favorites")}><span className="nav-icon">☆</span> 收藏 <b>{data.items.filter((item) => item.favorite).length}</b></button>
          <p className="nav-label categories-label">分类</p>
          {(Object.keys(categoryMeta) as Category[]).map((key) => <button key={key} className={category === key ? "active" : ""} onClick={() => setCategory(key)}><span className="nav-icon">{categoryMeta[key].glyph}</span> {categoryMeta[key].label}<b>{data.items.filter((item) => item.category === key).length}</b></button>)}
        </nav>
        <div className="sidebar-bottom">
          <button onClick={exportVault}><span>↓</span> 导出加密备份</button>
          <button onClick={() => importRef.current?.click()}><span>↑</span> 导入备份</button>
          <input ref={importRef} hidden type="file" accept="application/json,.json" onChange={(event) => { const file = event.target.files?.[0]; if (file) void importVault(file); event.currentTarget.value = ""; }} />
          <button onClick={lock}><span>⌁</span> 锁定保险库</button>
          <div className="local-status"><i /> 数据仅存储在此设备</div>
        </div>
      </aside>

      <section className="list-panel">
        <div className="panel-header"><div><span className="eyebrow">个人保险库</span><h1>{category === "all" ? "所有条目" : category === "favorites" ? "收藏" : categoryMeta[category].label}</h1></div><button className="mobile-new" onClick={openNew}>＋</button></div>
        <label className="search-box"><span>⌕</span><input value={query} onChange={(event) => setQuery(event.target.value)} placeholder="搜索保险库" /><kbd>⌘ K</kbd></label>
        <div className="item-count">{filtered.length} 个条目</div>
        <div className="item-list">
          {filtered.length === 0 ? <div className="empty-state"><div>＋</div><h2>{query ? "没有匹配的条目" : "保险库还是空的"}</h2><p>{query ? "试试其他关键词。" : "保存你的第一个登录信息或安全笔记。"}</p>{!query && <button onClick={openNew}>新建条目</button>}</div> : filtered.map((item) => (
            <button className={`item-row ${selected?.id === item.id ? "selected" : ""}`} key={item.id} onClick={() => { setSelectedId(item.id); setRevealed(false); }}>
              <span className={`item-avatar ${item.category}`}>{item.title.slice(0, 1).toUpperCase()}</span><span className="item-text"><strong>{item.title}</strong><small>{item.username || categoryMeta[item.category].label}</small></span>{item.favorite && <span className="favorite-star">★</span>}<span className="chevron">›</span>
            </button>
          ))}
        </div>
      </section>

      <section className="detail-panel">
        {selected ? <>
          <header className="detail-header"><div className={`detail-avatar ${selected.category}`}>{selected.title.slice(0, 1).toUpperCase()}</div><div><h2>{selected.title}</h2><p>{categoryMeta[selected.category].label}</p></div><div className="detail-actions"><button aria-label={selected.favorite ? "取消收藏" : "收藏"} onClick={() => void toggleFavorite(selected)}>{selected.favorite ? "★" : "☆"}</button><button onClick={() => openEdit(selected)}>编辑</button><button className="danger-action" aria-label="删除" onClick={() => void deleteItem(selected)}>•••</button></div></header>
          <div className="detail-body">
            <div className="field-group"><p className="field-label">登录信息</p><div className="value-row"><span><small>用户名</small><strong>{selected.username || "—"}</strong></span>{selected.username && <button onClick={() => void copy(selected.username, "用户名")}>复制</button>}</div><div className="value-row password-row"><span><small>密码</small><strong>{revealed ? selected.password : "••••••••••••••"}</strong></span><div><button onClick={() => setRevealed((value) => !value)}>{revealed ? "隐藏" : "显示"}</button>{selected.password && <button onClick={() => void copy(selected.password, "密码")}>复制</button>}</div></div></div>
            {selected.url && <div className="field-group"><p className="field-label">网站</p><div className="value-row"><a href={selected.url.startsWith("http") ? selected.url : `https://${selected.url}`} target="_blank" rel="noreferrer">{selected.url} <span>↗</span></a><button onClick={() => void copy(selected.url, "网址")}>复制</button></div></div>}
            {selected.notes && <div className="field-group"><p className="field-label">备注</p><p className="notes-value">{selected.notes}</p></div>}
            <p className="updated-time">上次更新于 {new Date(selected.updatedAt).toLocaleString("zh-CN")}</p>
          </div>
        </> : <div className="detail-empty"><div className="brand-mark">L</div><h2>选择一个条目</h2><p>查看、复制或编辑保存在保险库中的信息。</p></div>}
      </section>

      {editorOpen && <div className="modal-backdrop" role="presentation" onMouseDown={() => setEditorOpen(false)}><section className="editor" role="dialog" aria-modal="true" aria-labelledby="editor-title" onMouseDown={(event) => event.stopPropagation()}>
        <header><div><span className="eyebrow">加密条目</span><h2 id="editor-title">{editingId ? "编辑条目" : "新建条目"}</h2></div><button aria-label="关闭" onClick={() => setEditorOpen(false)}>×</button></header>
        <form onSubmit={saveItem}>
          <div className="category-picker">{(Object.keys(categoryMeta) as Category[]).map((key) => <button type="button" key={key} className={draft.category === key ? "active" : ""} onClick={() => setDraft({ ...draft, category: key })}><span>{categoryMeta[key].glyph}</span>{categoryMeta[key].label}</button>)}</div>
          <label>名称<input autoFocus required value={draft.title} onChange={(event) => setDraft({ ...draft, title: event.target.value })} placeholder="例如：GitHub" /></label>
          <label>用户名<input value={draft.username} onChange={(event) => setDraft({ ...draft, username: event.target.value })} placeholder="邮箱或用户名" /></label>
          <label>密码<div className="password-input"><input value={draft.password} onChange={(event) => setDraft({ ...draft, password: event.target.value })} /><button type="button" onClick={() => setDraft({ ...draft, password: makePassword() })}>重新生成</button></div></label>
          <label>网址<input value={draft.url} onChange={(event) => setDraft({ ...draft, url: event.target.value })} placeholder="https://example.com" /></label>
          <label>备注<textarea value={draft.notes} onChange={(event) => setDraft({ ...draft, notes: event.target.value })} placeholder="可选的安全备注" /></label>
          <label className="favorite-check"><input type="checkbox" checked={draft.favorite} onChange={(event) => setDraft({ ...draft, favorite: event.target.checked })} /> 添加到收藏</label>
          <footer><button type="button" onClick={() => setEditorOpen(false)}>取消</button><button className="primary-button">保存条目</button></footer>
        </form>
      </section></div>}
      {toast && <div className="toast" role="status">✓ {toast}</div>}
    </main>
  );
}
