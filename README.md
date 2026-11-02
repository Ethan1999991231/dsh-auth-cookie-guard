# dsh-auth-cookie-guard

**修复 DeepSeek Harness 反复开关约 71 次后窗口打不开的问题。**
A Host plugin that stops the port-bound `dsh-auth-*` browser cookies from piling up
across desktop launches — and heals a profile that already hit the HTTP header limit.

---

## 故障链路（源码定位）

| 环节 | 事实 | 出处 |
| --- | --- | --- |
| 每次启动换端口 | 桌面壳用 `--port 0` 拉起 Host，端口由系统随机分配 | `dsh-desktop-host/lib/index.js` → `args: ["--no-open","--host","127.0.0.1","--port","0"]` |
| Cookie 绑定 host:port | `cookieName(authority) = 'dsh-auth-' + base64url(sha256(authority))`，`authority = '127.0.0.1:<port>'` | `dsh-client-connection/lib/index.js:335` `cookieName()`、`:307` `requestAudience()` |
| 有效期 30 天 | `cookieMaxAgeDays: z.natural().min(1).default(30)` | `dsh-client-connection/lib/index.js:1017` |
| 从不清理旧端口 | 只有新 cookie 的 `Set-Cookie`，没有任何过期旧 cookie 的代码 | 同上，`authorizeIndex` / `authorizeConnect` |
| 浏览器按 host 聚合 | Cookie 不区分端口，所有历史端口的 `dsh-auth-*` 都会进同一个 `127.0.0.1` 的 `Cookie` 请求头 | RFC 6265 |
| 服务端 16KB 上限 | `createServer(listener)` 未传 `maxHeaderSize` → Node 默认 16384 字节，超限直接 `HPE_HEADER_OVERFLOW`，窗口白屏 / 加载失败 | `dsh-host-webserver/lib/index.js:412` |

算一下阈值：单条 Cookie 头约 225 字节（名字 52 + 值 170 + 分隔符），请求其余头部约 460 字节，
`(16384 - 460) / 225 ≈ 70.8` → **第 71 次开关正好越界**，与现象完全吻合。

## 插件做了什么

1. **回收（治本）**：`dsh-host-frontend-static` 对首页和每个静态资源都会调用 `connection.authorizeIndex(req,res)`。
   插件包裹该方法，在写响应时给所有「不属于当前端口」的 `dsh-auth-*` Cookie 追加
   `Set-Cookie: <name>=; Max-Age=0; Path=/; Expires=Thu, 01 Jan 1970 00:00:00 GMT`。
   一旦 jar 超过 4 条（见下面的滞回阈值）就回收到只剩当前端口那一条，**上限被钉死在 5 条以内**，不会累积到 71。
2. **自愈（治已坏）**：已经堆满的旧 jar 请求根本到不了业务代码，但 Node 仍会抛出
   `clientError` + `HPE_HEADER_OVERFLOW`，并带 `err.rawPacket`（被截断的原始请求字节，里面有 Cookie 名和原始 URL）。
   插件据此直接回 `303 See Other` 到原 URL（保留 `?token=`），并逐条带上过期 Cookie；
   浏览器丢弃这些 Cookie 后自动重试，几跳之内就能正常打开，**不需要手动清缓存**。
3. **诊断**：状态落到 `$DSH_HOME/auth-cookie-guard/state.json`，含回收次数、见过的最大 jar、溢出修复次数。

### 安全边界（避免误删别人的登录态）

- **滞回阈值 `REAP_ABOVE = 4`**：jar 里 `dsh-auth-*` 不超过 4 条时完全不动手。单次启动稳定在 1 条，
  只有反复开关才会超过阈值；这样同一 `DSH_HOME` 下并行运行的另一个 Harness 实例（它有自己的 authority Cookie）不会被误登出。
- **只清自己发出的那批名字**：过期头只为「本次请求 Cookie 头里真实出现过的名字」下发，不会凭猜测构造名字。
- **同主机校验**：只有当请求 authority 的 hostname 等于本监听器 hostname（`webServer.getOrigin()`）时才回收，
  远程 / 局域网 authority 的请求不会触发清理。
- **Secure 对齐**：监听器是 https 时，过期 Cookie 同样带 `Secure`（否则浏览器会拒绝覆盖原 Secure Cookie）。

插件完全防御式实现：不改请求业务逻辑、不改配置文件、`ctx.effect` 卸载时还原被包裹的方法；
内部结构变化时退化为 no-op 并打日志，不会把应用弄坏。

## 安装

需要 DeepSeek Harness **0.2.1-rc.5 或更新**（依赖 `connection.browserAuth` 与公开的 `webServer.server`）。

```bash
# 1) 从 npm
dsh plugin --profile desktop add dsh-auth-cookie-guard

# 2) 从 Release 里的 tarball
dsh plugin --profile desktop add ./dsh-auth-cookie-guard-1.0.0.tgz

# 3) 从本地源码（link，改完即时生效）
dsh plugin --profile desktop add ./
```

装完重启一次 Harness。之后可以看 `$DSH_HOME/auth-cookie-guard/state.json` 确认它在干活：

```json
{ "reaped": 12, "reapEvents": 5, "overflowRepairs": 0, "maxJarSeen": 3, "errors": 0 }
```

`overflowRepairs` 大于 0 说明某次启动撞上了已经堆满的旧 jar，被自愈救回来了。

## 验证

```bash
npm test        # 真起 node:http 服务，10 项断言：阈值、保留当前 Cookie、同主机保护、
                # 过期属性、16KB 溢出自愈、卸载还原
npm run check   # node --check index.js
```

测试不依赖任何 npm 包，也不读写真实 cookie jar（全部用伪造的 `dsh-auth-*` 名字）。
tarball 里也带了这套测试，所以拿到包的人可以直接验证：

```bash
tar -xzf dsh-auth-cookie-guard-1.0.0.tgz && cd package && node test/guard.test.mjs
```

## 构建发布

```bash
node build.mjs --git                # 产出 release/ 三项，并给 release 树建好首个提交
node build.mjs --owner 你的GitHub用户名   # 额外写入 repository/homepage/bugs
```

产出 `release/` 下三样东西：

| 产物 | 用途 |
| --- | --- |
| `dsh-auth-cookie-guard/` | 干净的 git-ready 目录树（`--git` 时已初始化并提交），推 GitHub 用 |
| `dsh-auth-cookie-guard-1.0.0.tgz` | npm 包，`dsh plugin add` / `npm i` 用 |
| `dsh-auth-cookie-guard-1.0.0-source.zip` | 同一棵树的压缩包，直接上传 GitHub |
| `SHA256SUMS.txt` | 两个压缩包的校验和 |

`--owner` 会写入 `repository` / `homepage` / `bugs` 三个字段；不传则省略它们（npm 允许，可以直接 `npm publish`）。
重复执行 `build.mjs` 会重建 `release/`，但里面已有的 `.git` 会被保留（先挪到同盘暂存目录再挪回），
所以可以「改代码 → 重新 build → 继续提交」，历史不会丢。

两条 GitHub Actions 都在仓库里：

- `.github/workflows/ci.yml` — 每次 push / PR 在 Node 20、22、24 上跑 `node --check` 与 `npm test`。
- `.github/workflows/release.yml` — 推 `v*` tag 时重新构建，并把 tgz、源码 zip、`SHA256SUMS.txt` 附到 GitHub Release。

> 仓库里的 `package.json` 用 `@local/dsh-auth-cookie-guard` 这个名字，是为了能在本地 profile 里
> 以 `link:` 方式装上、同时不和已发布的 npm 包名冲突。`build.mjs` 会把包名、以及 `cordis.patch.yml`
> 里引用它的那一行一起改写成发布名。

## 目录结构

```
index.js                 Host 插件本体（回收 + 溢出自愈 + 诊断落盘）
cordis.patch.yml         bundle 插入行（loader 行 id: dsh-auth-cookie-guard）
locale/{en,zh}.json      插件管理页标题与说明
icon.svg                 插件图标
test/guard.test.mjs      回归测试（零依赖）
build.mjs                发布构建脚本
.github/workflows/ci.yml     Node 20/22/24 上跑语法检查与测试
.github/workflows/release.yml 推 tag 时构建并附产物到 Release
.gitattributes           统一 LF 行尾
```

## 说明

- 这不是 DeepSeek Harness 官方代码；官方修复方向应是「启动时清理与本实例 authority 不一致的
  `dsh-auth-*` Cookie」，或把 cookie 名字里的端口去掉（cookie 本就不区分端口）。
- 插件只操作 `dsh-auth-` 前缀、且出现在当前请求 `Cookie` 头里的名字，不读凭据文件、不联网。

MIT License.
