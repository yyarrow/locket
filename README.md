# Locket

一个面向免费公测的零知识密码管理器。保险库只在浏览器中解密，服务端通过 Vercel + Neon 同步密文，不上传主密码、恢复密钥或条目明文。

## 功能

- 邮箱一次性链接登录、开放注册与可撤销会话
- Argon2id 密钥派生与 AES-256-GCM 信封加密
- 独立恢复密钥，可在忘记主密码后重新包装数据密钥；支持主密码更换与恢复密钥轮换
- Neon 密文同步与乐观并发控制
- 登录、API Token、TOTP、银行卡、安全笔记与 Wi-Fi 分类；安全笔记支持 Markdown 编辑与预览
- 搜索、收藏、密码生成与复制
- 本地识别二维码截图并生成 TOTP 动态验证码，支持 `otpauth://` 链接和 Base32 设置密钥
- 5 分钟无操作自动锁定
- 手机端自适应保险库与安全中心
- 加密备份导入与导出；恢复前先在本地解密校验并自动保存当前密文备份
- 登录设备管理，以及经邮箱链接二次确认的账号与云端数据删除
- 每个账号最多 500 个条目

## 本地运行

需要 Node.js 22.13 或更高版本，以及独立的 Neon PostgreSQL 数据库。复制 `.env.example` 为 `.env.local` 并填写配置，然后执行：

```bash
npm install
npm run db:migrate
npm run dev
```

生产构建和检查：

```bash
npm run build
npm run typecheck
npm test
```

生产环境必须配置 `DATABASE_URL`、`AUTH_SECRET` 和 `EMAIL_FROM`，邮件可选择 `RESEND_API_KEY` 或 `SMTP_*`。`APP_URL` 未设置时自动使用 Vercel 生产域名；`REGISTRATION_MODE=open` 允许新邮箱通过一次性链接创建账号，改为其他值后仅现有账号可以登录。

## 安全边界

这是可用的公测版本，并非经过独立安全审计的正式密码管理器。恢复密钥丢失且忘记主密码后，保险库无法恢复。正式承载高价值凭据前，应完成专业密码学审计、依赖审计、浏览器威胁模型评审，并补齐隐私政策等合规材料。

上线准备材料：

- [上线前安全检查清单](./docs/security/launch-readiness.md)
- [OWASP ASVS 5.0 优先差距表](./docs/security/asvs-5.0-gap-assessment.md)

## 许可证

[MIT](./LICENSE)
