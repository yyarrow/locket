# Locket 上线前安全检查清单

更新日期：2026-07-29

线上代码基线：`4f3e432e27bda847565d1d7e3d8e0ee6d5f558f7`；当前工作区继续进行会话与 API 安全收口

线上目标：`https://locket.warmbeing.com`

评估范围：当前 Web 客户端、Next.js API、Vercel 部署、Neon 密文存储与 GitHub 仓库配置

## 当前结论

当前版本可以继续作为明确标注风险的免费公测版，但不应当以“经过安全认证”或“适合承载高价值凭据”的正式版本发布。

正式上线结论仍为 **NO-GO**，直到下方剩余 P0 阻断项完成。本文是内部上线准备检查，不是独立安全审计，也不代表通过 OWASP ASVS 认证。

## 已验证的基线

- [x] `npm test`：18/18 通过。
- [x] `npm run lint`：通过。
- [x] `npm run typecheck`：通过。
- [x] `npm run build`：生产构建通过。
- [x] `npm audit --omit=dev`：生产依赖 0 个已知漏洞。
- [x] HTTPS：HTTP 自动 308 跳转 HTTPS，线上证书可正常访问。
- [x] 页面响应：已观察到 CSP、HSTS、`no-store`、`nosniff`、`Referrer-Policy: no-referrer`。
- [x] 代码仓库：未跟踪 `.env.local`，GitHub secret scanning 与 push protection 已启用。
- [x] 零知识基础边界：保险库条目在浏览器端使用随机 DEK 加密，服务端 schema 仅保存密文、包装密钥和必要元数据。
- [x] 账号删除：邮箱链接二次确认后级联删除用户、会话、令牌和云端密文。

## P0：正式上线阻断项

| ID | 当前风险 | 当前证据 | 完成标准 |
| --- | --- | --- | --- |
| P0-01 ✅ | 生产依赖漏洞已解决并部署 | Next.js 16.2.12、sharp 0.35.3；测试、lint、typecheck、build 均通过；`npm audit --omit=dev` 为 0；线上部署为 `4f3e432` | 后续发布持续执行生产依赖审计与线上冒烟检查 |
| P0-02 | 尚无独立产品安全与密码学审计 | README 已明确声明未审计 | 第三方完成威胁模型、密码学协议、源代码、Web/API 渗透测试及修复复测；保留可公开的报告摘要 |
| P0-03 | Web 分发模型未进入“零知识”威胁声明 | 托管端若被攻陷，可向浏览器下发恶意一方 JavaScript；CSP 无法防御被授权的一方代码 | 安全文档明确哪些服务器/CDN/发布链攻击不在零知识保证内；建立受保护发布流程、构建溯源和部署审计 |
| P0-04 | 会话与登录链接仍有剩余收紧项 | 当前工作区已完成 `__Host-` Cookie、旧会话轮换、7 天空闲超时和页面载入后的 query 清理；移除其他会话仍不要求重新验证，邮件令牌的初始请求仍可能进入基础设施日志 | 完成敏感操作再验证，并评估 fragment 或一次性中转码以避免令牌出现在初始 URL query；部署后复验 Cookie 与会话行为 |
| P0-05 | 缺少可用的安全监控和事件响应 | 只有零散 `console.error`；无认证/授权/安全控制事件清单、告警或响应手册 | 建立不记录密钥和密文内容的结构化安全日志、告警、保留策略和事件响应流程，并验证时钟与访问控制 |
| P0-06 | 软件供应链保护不足 | `main` 未保护、无 GitHub Actions、Dependabot alerts/security updates 未启用 | 启用分支保护、必需检查、依赖告警/安全更新；CI 至少运行 test、lint、typecheck、build、生产依赖审计 |
| P0-07 | 对外政策与漏洞入口缺失 | `/.well-known/security.txt`、`/privacy`、`/terms` 当前均为 404 | 发布隐私政策、服务条款、数据保留/删除说明、漏洞披露政策与 `security.txt` |
| P0-08 | “银行卡”分类造成支付数据合规歧义 | 当前通用字段可被用于保存卡号、CVV 或 PIN | 正式上线前移除该分类，或明确限制为名称/末四位/到期提醒并禁止保存 CVV、CVC、PIN；由合规专业人员确认范围 |

## 产品与密码学检查

- [x] DEK、恢复密钥、认证令牌均来自 CSPRNG。
- [x] AES-256-GCM 提供密文机密性和完整性；每次加密生成 96 位随机 IV。
- [x] 主密码经 Argon2id 派生包装密钥，主密码与恢复密钥不上传。
- [x] DEK 以不可导出的 Web Crypto `CryptoKey` 保留在运行时。
- [x] 主密码更换和恢复密钥轮换只重新包装 DEK。
- [x] 5 分钟无操作后清除解密数据和 DEK 引用。
- [x] 加密备份恢复前先本地解密、校验，并自动下载当前密文备份。
- [ ] 建立密码学资产清单：算法、实现库、用途、密钥长度、生命周期、存放位置和迁移方案。
- [ ] 在目标手机和桌面浏览器上基准测试 Argon2id；当前参数是通用最低基线，需针对可离线破解的保险库模型给出书面依据。
- [ ] 审核 AEAD AAD 设计，将版本、用户/保险库标识和必要元数据纳入认证边界。
- [ ] 设计服务端回滚/旧密文重放的检测或明确接受该风险；当前 `revision` 只能防止正常 API 并发覆盖，不能防数据库控制者回滚。
- [ ] 审核密码生成器的均匀抽样、恢复流程、旧 LK1 格式兼容和失败行为。
- [ ] 明确浏览器内存、恶意扩展、XSS、剪贴板、截屏和同一保险库保存密码与 TOTP 的风险边界。

## 认证、会话与授权检查

- [x] 邮箱登录令牌随机生成、服务端仅存哈希、15 分钟失效且只能消费一次。
- [x] 登录邮件请求按 IP 与邮箱限流；删除账号邮件请求按用户限流。
- [x] 会话令牌随机生成、数据库仅存哈希；Cookie 为 `HttpOnly`、生产环境 `Secure`、`SameSite=Lax`。
- [x] 状态修改 API 在生产环境强制同源 `Origin`。
- [x] 保险库和会话查询均以服务端当前用户 ID 约束。
- [x] 会话可以列出并逐个撤销，账号禁用或删除后不能继续使用。
- [x] 生产会话 Cookie 使用 `__Host-locket_session`，保持 `Secure`、`Path=/` 且不设置 `Domain`；旧 Cookie 在有效请求后自动迁移。
- [x] 每次成功登录时轮换并终止浏览器原有会话。
- [x] 服务端会话为 7 天空闲失效、30 天绝对失效；`lastSeenAt` 最多每 15 分钟刷新一次以限制数据库写入。
- [ ] 撤销其他会话前要求一次邮箱再验证或等价的近期认证。
- [x] 邮件链接页面载入后立即用 `history.replaceState` 清理浏览器地址和历史中的 query。
- [ ] 进一步评估使用 URL fragment 或一次性中转码，避免令牌进入首次请求与基础设施日志。
- [ ] 为登录、令牌验证、会话撤销、账号删除增加动态和跨用户授权测试。

## Web、API 与数据保护检查

- [x] 页面 CSP 使用逐响应 nonce，禁止 object、base、frame 与外部连接。
- [x] Markdown 禁止原始 HTML 与外部图片，链接新窗口使用 `noopener noreferrer`。
- [x] TOTP 二维码只在本地解析，并限制为 15 MB、最长边 2600 px。
- [x] 服务端校验密文格式、KDF 参数、条目数量和字段长度，并使用乐观并发控制。
- [x] 敏感页面与已认证数据 API 返回 `Cache-Control: no-store`。
- [x] 当前工作区已让 API 和错误响应继承统一安全头；部署后需复验 `/api/auth/me` 的 CSP、`nosniff`、Referrer-Policy 与完整 HSTS。
- [x] 备份导入在执行 `file.text()` 前限制为 8 MB；服务端密文字段上限仍为约 7 MB Base64。
- [ ] 为所有公开 API 记录请求体、字段、数量、频率和资源限制；不要只依赖 Vercel 的隐式上限。
- [ ] 验证 Neon、Resend/SMTP 的强制 TLS 与证书验证；SMTP 生产配置应禁止明文回退。
- [ ] 明确服务端可见元数据：邮箱、条目数量、更新时间、会话 user-agent 和加盐/加密域分离后的 IP 哈希用途与保留时间。
- [ ] 定期清理过期 session、auth token 和 rate-limit 记录。

## 工程、运维与合规检查

- [ ] 定义漏洞修复时限，例如 critical 24 小时、high 7 天、medium 30 天，并记录例外审批。
- [x] 当前生产依赖已无 npm 已知漏洞。
- [ ] 跟踪开发工具链 `brace-expansion` 的 [GHSA-mh99-v99m-4gvg](https://github.com/advisories/GHSA-mh99-v99m-4gvg)：完整 audit 在 ESLint 9 的 9 个传递路径中报告 high；强升 ESLint 10 会破坏当前 Next React 插件，暂不使用 `--force`。
- [ ] 每次发布生成 SBOM，保存依赖锁文件和构建产物摘要。
- [ ] 保护 Vercel、Neon、域名、GitHub 和邮件账号，全部启用抗钓鱼 MFA/Passkey，限制管理员数量。
- [ ] 建立生产配置清单与轮换周期：`AUTH_SECRET`、数据库凭据、SMTP/Resend 凭据、部署令牌。
- [ ] 备份只覆盖服务端密文，定期演练数据库恢复、用户备份恢复和账号删除。
- [ ] 明确隐私请求渠道、数据保留周期、跨境处理方和子处理方。
- [ ] 建立版本发布记录，确保线上 commit、审计 commit 和公开报告可对应。
- [ ] 公测页面持续显示“尚未独立审计，不建议存放高价值生产凭据”，直到 P0-02 完成。

## 发布验证命令

每个候选版本至少执行：

```bash
npm test
npm run lint
npm run typecheck
npm run build
npm audit --omit=dev --audit-level=low
```

同时执行线上只读检查：

```bash
curl -I http://locket.warmbeing.com/
curl -I https://locket.warmbeing.com/
curl -I https://locket.warmbeing.com/api/auth/me
curl -I https://locket.warmbeing.com/.well-known/security.txt
```

## 相关材料

- [OWASP ASVS 5.0.0 stable release](https://github.com/OWASP/ASVS/releases/tag/v5.0.0_release)
- [Locket ASVS 5.0 优先差距表](./asvs-5.0-gap-assessment.md)
- [PCI SSC：加密不会自动让卡数据脱离 PCI DSS 范围](https://www.pcisecuritystandards.org/faqs/1086/)
- [PCI SSC：授权后不得存储敏感认证数据](https://www.pcisecuritystandards.org/faqs/1533/)
