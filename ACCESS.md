# Cloudflare Access 登录

此 Fork 支持以 Cloudflare Access 作为唯一浏览器登录方式。默认保持原密码认证；只有完成 Access 应用设置后才启用 `cloudflare-access` 模式。

## 应用与上报入口

为正式域名创建 hostname-based Self-hosted Access 应用，选择 GitHub 身份提供商，Allow 条件限定本人实际邮箱，并要求相应登录方式。应用的 AUD 只用于当前监控。Worker-level Access 当前不支持 WebSocket，不适用于此面板。

为正式域名的 `/update` 创建更具体的 Bypass 应用，避免现有 HTTP 探针被重定向至登录页面。Worker 仍然只允许精确的 `POST /update` 作为机器入口，并由原上报处理器校验 `API_SECRET`。不要为 `/api/*` 或整个域名设置 Bypass。

此 Fork 的生产入口在 `.github/workflows/deploy.yml` 中配置。备用 workers.dev 域名只允许探针上报，其余请求即使带有效 Access 身份也会被拒绝。Preview URLs 保持关闭，静态资源必须配置 `assets.run_worker_first=true`。

## GitHub Actions 配置

| 类型 | 名称 | 内容 |
| --- | --- | --- |
| Repository variable | `MONITOR_AUTH_MODE` | 默认 `password`；启用时设为 `cloudflare-access` |
| Repository variable | `ACCESS_TEAM_DOMAIN` | 实际 `https://<team>.cloudflareaccess.com`，无额外路径 |
| Repository variable | `ACCESS_AUD` | 当前监控主应用的 AUD |
| Repository secret | `ACCESS_ALLOWED_EMAILS` | 本人实际邮箱；多个邮箱以逗号分隔 |
| Repository secret | `API_SECRET` | 现有探针上报密钥 |

工作流把邮箱白名单和探针密钥写为加密 Worker Secrets；Team domain、AUD、正式与备用主机名作为普通变量。OAuth Client Secret 直接配置在 Cloudflare 的 GitHub 身份提供商中，不交给 Worker、GitHub Actions 或探针。

Worker 需要以下绑定：

```text
AUTH_MODE=cloudflare-access
ACCESS_TEAM_DOMAIN=https://<team>.cloudflareaccess.com
ACCESS_AUD=<当前监控主应用的64位AUD>
ACCESS_ALLOWED_EMAILS=<本人实际邮箱，Worker Secret>
ACCESS_HOSTNAME=<正式主机名>
AGENT_REPORT_HOSTNAMES=<备用上报主机名，逗号分隔>
```

启用后，Worker 验证 `Cf-Access-Jwt-Assertion` 的签名、issuer、AUD、有效期、应用令牌类型与用户邮箱。单独的邮箱头、Access Cookie 或旧面板 JWT 不构成有效身份。配置缺失或错误时拒绝访问。

后台直接识别 Access 身份，隐藏本地账号、密码、JWT 和 Turnstile 登录设置，退出时进入 `/cdn-cgi/access/logout`。旧面板密码和会话不参与认证；设置保存不能恢复公开访问。

## 发布与验收

1. 先以默认密码模式发布代码，确认面板、历史数据、浏览器 WebSocket 与全部探针正常。
2. 完成真实 GitHub 身份测试，记录实际返回的邮箱，不根据 GitHub 用户名猜测邮箱。
3. 建立正式域名应用、本人策略和精确上报路径例外，配置相应 variables / secrets。
4. 将 `MONITOR_AUTH_MODE` 设为 `cloudflare-access`，手动触发部署。
5. 用无痕窗口验证登录与注销、后台设置、历史查询、实际 WebSocket；检查匿名访问和备用域名被拒绝，六台探针连续两个周期上报。

本地验证：

```sh
pnpm run test:all
pnpm run build:frontend
pnpm exec wrangler deploy --dry-run --outdir /tmp/cf-monitor-access-worker
```

本地签名测试不能代替真实 OAuth 与边缘 Access 策略验收。启用前保留旧部署和数据库认证设置备份；回滚时同时核对 Access 策略、Worker 模式以及备用入口。

## 官方文档

- [GitHub 身份提供商](https://developers.cloudflare.com/cloudflare-one/integrations/identity-providers/github/)
- [验证 Access JWT](https://developers.cloudflare.com/cloudflare-one/access-controls/applications/http-apps/authorization-cookie/validating-json/)
- [Workers 与 Access](https://developers.cloudflare.com/workers/configuration/cloudflare-access/)
