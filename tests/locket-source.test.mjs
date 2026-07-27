import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

const read = (path) => readFile(new URL(path, import.meta.url), "utf8");

test("encrypts the vault in the browser with a random data key and recovery key", async () => {
  const source = await read("../lib/vault-crypto.ts");
  assert.match(source, /argon2idAsync/);
  assert.match(source, /AES-GCM/);
  assert.match(source, /dataKeyBytes = crypto\.getRandomValues/);
  assert.match(source, /recoveryWrappedKey/);
  assert.match(source, /recoverAndRekeyVault/);
});

test("sync schema contains ciphertext metadata but no vault plaintext fields", async () => {
  const schema = await read("../db/schema.ts");
  assert.match(schema, /ciphertext: text/);
  assert.match(schema, /wrappedKey: text/);
  assert.match(schema, /recoveryWrappedKey: text/);
  assert.doesNotMatch(schema, /username:|password:|notes:/);
});

test("account and session safeguards remain enabled", async () => {
  const [emailLink, verify, session, limiter, vaultRoute] = await Promise.all([
    read("../app/api/auth/email-link/route.ts"),
    read("../app/api/auth/verify/route.ts"),
    read("../lib/session.ts"),
    read("../lib/rate-limit.ts"),
    read("../app/api/vault/route.ts"),
  ]);
  assert.match(emailLink, /REGISTRATION_MODE/);
  assert.match(emailLink, /isSameOrigin/);
  assert.match(emailLink, /checkRateLimit/);
  assert.match(verify, /createSession/);
  assert.match(session, /httpOnly: true/);
  assert.match(session, /sameSite: "lax"/);
  assert.match(limiter, /on conflict \(key\) do update/);
  assert.match(vaultRoute, /eq\(vaults\.revision, payload\.revision\)/);
});

test("client keeps local safety controls without plaintext persistence", async () => {
  const source = await read("../app/vault-app.tsx");
  assert.match(source, /AUTO_LOCK_MS/);
  assert.match(source, /主密码至少需要 12 个字符/);
  assert.match(source, /加密备份/);
  assert.match(source, /navigator\.clipboard/);
  assert.doesNotMatch(source, /localStorage|sessionStorage|indexedDB/);
  assert.doesNotMatch(source, /登录密码|\/api\/auth\/login|\/api\/auth\/register/);
});

test("TOTP QR images are decoded locally and destructive actions are explicit", async () => {
  const [app, qrDecoder] = await Promise.all([
    read("../app/vault-app.tsx"),
    read("../lib/totp-qr.ts"),
  ]);
  assert.match(app, /type Category = "login" \| "token" \| "totp"/u);
  assert.match(app, /totp: \{ label: "TOTP"/u);
  assert.match(app, /password: isTotpDraft \|\| emptyNewNoteCredentials \? "" : draft\.password/u);
  assert.match(app, /!isTotpDraft && !isNoteDraft && <label>密码/u);
  assert.match(app, /showTotpEditor &&/u);
  assert.match(app, /window\.addEventListener\("paste", pasteImage\)/u);
  assert.match(app, /navigator\.clipboard\?\.read/u);
  assert.match(app, />粘贴二维码截图<\/button>/u);
  assert.match(app, /const itemCategory = contextualCategory \?\? "login"/u);
  assert.match(app, /itemCategory === "token" \? makeToken\(\) : itemCategory === "totp" \|\| itemCategory === "note" \? "" : makePassword\(\)/u);
  assert.match(app, /\(editingId \|\| !contextualCategory\) && <div className="category-picker"/u);
  assert.match(app, /扫描二维码/);
  assert.match(app, /className="danger-action"/u);
  assert.match(app, />删除<\/button>/u);
  assert.doesNotMatch(app, />•••</u);
  assert.match(qrDecoder, /jsQR/);
  assert.match(qrDecoder, /document\.createElement\("canvas"\)/);
  assert.doesNotMatch(qrDecoder, /fetch\(|XMLHttpRequest|FormData/);
});

test("secure notes use bounded Markdown without credential fields or remote images", async () => {
  const app = await read("../app/vault-app.tsx");
  assert.match(app, /import Markdown from "react-markdown"/u);
  assert.match(app, /<Markdown\s+skipHtml/u);
  assert.match(app, /img: \(\{ alt \}\) => <span className="markdown-image-disabled"/u);
  assert.match(app, /const isNoteDraft = draft\.category === "note"/u);
  assert.match(app, /!isNoteDraft && !isTokenDraft && <label>\{isTotpDraft \? "账号" : "用户名"\}/u);
  assert.match(app, /安全笔记内容不能超过 256 KB/u);
  assert.match(app, /isNoteDraft \? "标题" : "名称"/u);
  assert.match(app, /Markdown 纯文本 · 不支持 HTML、外部图片或附件/u);
  assert.match(app, /安全笔记显示模式/u);
});

test("API tokens are standalone encrypted entries with dedicated secret controls", async () => {
  const app = await read("../app/vault-app.tsx");
  assert.match(app, /token: \{ label: "API Token"/u);
  assert.match(app, /const isTokenDraft = draft\.category === "token"/u);
  assert.match(app, /crypto\.getRandomValues\(new Uint8Array\(32\)\)/u);
  assert.match(app, /username: isTokenDraft \|\| emptyNewNoteCredentials \? "" : draft\.username/u);
  assert.match(app, /type=\{tokenInputRevealed \? "text" : "password"\}/u);
  assert.match(app, />随机生成<\/button>/u);
  assert.match(app, /void copy\(selected\.password, "Token"\)/u);
  assert.match(app, /selected\.category === "token" \? "API 地址" : "网站"/u);
});

test("mobile vault navigation exposes categories and item details", async () => {
  const [app, styles] = await Promise.all([
    read("../app/vault-app.tsx"),
    read("../app/globals.css"),
  ]);
  assert.match(app, /mobileMenuOpen/u);
  assert.match(app, /mobileDetailOpen/u);
  assert.match(app, /aria-label="打开菜单"/u);
  assert.match(app, /aria-label="返回条目列表"/u);
  assert.match(styles, /\.sidebar\.mobile-open \{ transform: translateX\(0\); \}/u);
  assert.match(styles, /\.app-shell\.mobile-detail-open \.detail-panel/u);
});

test("backup restore validates locally before replacing the remote vault", async () => {
  const app = await read("../app/vault-app.tsx");
  assert.match(app, /const unlocked = await unlockVault<unknown>\(pendingBackup\.envelope, backupPassword\)/u);
  assert.match(app, /isVaultData\(unlocked\.data\)/u);
  assert.match(app, /downloadEnvelope\(envelope, "locket-before-restore"\)/u);
  assert.match(app, /await putEnvelope\(\{ \.\.\.pendingBackup\.envelope, revision: envelope\.revision \}\)/u);
  assert.match(app, /验证成功前，不会修改云端保险库/u);
  assert.match(app, /我了解验证成功后，当前云端保险库将被此备份替换/u);
});
