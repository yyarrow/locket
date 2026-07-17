# Locket

一个面向免费公测的零知识密码管理器。保险库只在浏览器中解密，服务端通过 Vercel + Neon 同步密文，不上传主密码、恢复密钥或条目明文。

## 功能

- 邮箱一次性链接登录、开放注册与可撤销会话
- Argon2id 密钥派生与 AES-256-GCM 信封加密
- 独立恢复密钥，可在忘记主密码后重新包装数据密钥
- Neon 密文同步与乐观并发控制
- 登录、银行卡、安全笔记与 Wi-Fi 分类
- 搜索、收藏、密码生成与复制
- 5 分钟无操作自动锁定
- 加密备份导入与导出
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

这是可用的公测版本，并非经过独立安全审计的正式密码管理器。恢复密钥丢失且忘记主密码后，保险库无法恢复。正式承载高价值凭据前，应完成专业密码学审计、依赖审计、浏览器威胁模型评审，以及隐私政策和数据删除流程。

## 许可证

[MIT](./LICENSE)
