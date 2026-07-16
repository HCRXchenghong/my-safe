# My Safe：轻量化 24 小时服务器安全防护方案

> 我的安全我自己来保障
>
> 项目代号：My Safe / XGuard
>
> 目标平台：Ubuntu 22.04 / 24.04、Debian 12 / 13（amd64 / arm64、systemd）
>
> 核心技术：Go、Nginx、Coraza WAF、MySQL / PostgreSQL、Flutter App
>
> 产品形态：服务器 Agent + 可选安全 BFF/WAF + 无 Web 页面的控制服务 + 手机 App + 开放 API

## 当前可运行实现（2026-07-16）

仓库已经从产品方案推进到可运行原型，但**尚不是可直接承诺生产安全的完整 Beta**。当前实现坚持无 Web 管理页面，并已打通 Agent、控制面和 Gateway 的真实请求链路。

| 模块 | 当前能力 | 验证状态 |
|---|---|---|
| Control Plane | Agent 注册、Ed25519 client CA、Token+mTLS 双身份、证书轮换、幂等事件、乐观并发策略、原子审计、严格 JSON/脱敏 | 真实 TLS 注册→mTLS→轮换及策略/审计测试通过 |
| Agent | 稳定机器身份、AES-256-GCM 队列、文件/SSH/进程/端口探针、Gateway 本地事件、单调策略、断线续传 | 正文/原始日志/命令行不出端，检测与策略真实链路通过 |
| Gateway | Coraza 3.7 + OWASP CRS 4.25，三模式、fail-open/closed、最小化规则事件、离线 outbox | 攻击代理、秘密不出端、离线恢复组件测试通过；完整 Unix 链路待 Linux CI |
| 数据库 | 统一 Repository 契约、PostgreSQL 14～18 与 MySQL 8.0/8.4 迁移和运行模式 | 本地契约测试框架通过；CI 配置真实双库服务 |
| 交付 | 环境探测、Ed25519 签名清单、SHA-256、事务安装/回滚、Nginx 安全接入、Linux amd64/arm64、systemd、OpenAPI 3.1、签名发布流水线 | 故障注入、篡改拒绝、YAML/Bash/actionlint、交叉构建测试通过；真实发行版主机矩阵待跑 |

### 受保护主机一键接入

前提是已经部署 My Safe Control Plane，并为这台主机创建了一个短时、一次性 Bootstrap Token。正式 tag 发布后，把下面的 `<VERSION>`、控制面地址和令牌文件替换为实际值：

```bash
curl -fsSL --proto '=https' "https://github.com/HCRXchenghong/my-safe/releases/download/<VERSION>/bootstrap.sh" | sudo bash -s -- --version <VERSION> --control-url https://control.example.com --bootstrap-token-file /root/my-safe-bootstrap-token --gateway auto
```

该入口只接受 HTTPS（测试时只额外接受回环 HTTP），先使用脚本内固定的 Ed25519 公钥验证发布清单，再校验当前架构的 Installer、Agent 和 Gateway SHA-256，最后才执行环境探测与事务安装。请求版本必须与签名清单完全一致。发布公钥指纹为：

```text
SHA256:dfd8edaae2af4eb157226cb86b95353ad7dcb6cc058fe940585739e05110075b
```

`--gateway auto` 只在找到唯一、字面量、回环地址的 Nginx `proxy_pass` 时接入 Gateway；其他拓扑仍会安装 Sensor，并明确说明没有获得 WAF 流量拦截能力。高保证环境建议先下载并审阅 `bootstrap.sh`，再执行；完整边界见 [`docs/COMPATIBILITY.md`](docs/COMPATIBILITY.md)。

只看计划、不写入系统：

```bash
sudo bash bootstrap.sh --version <VERSION> --control-url https://control.example.com --gateway auto --dry-run
```

### 本地快速运行

要求 Go 1.26。以下 PowerShell 示例只用于本机开发，令牌不能用于生产：

```powershell
$env:MYSAFE_STORE = "memory"
$env:MYSAFE_BOOTSTRAP_TOKEN = "local-bootstrap-token-change-me-32"
$env:MYSAFE_ADMIN_TOKEN = "local-admin-token-change-me-32-bytes"
go run ./cmd/mysafe-control
```

另开一个终端，注册并运行一次 Agent 扫描：

```powershell
go run ./cmd/mysafe-agent `
  --control-url http://127.0.0.1:8080 `
  --bootstrap-token "local-bootstrap-token-change-me-32" `
  --state-dir ./.local/agent `
  --once
```

查询控制面中的 Agent 和告警：

```powershell
$headers = @{ Authorization = "Bearer local-admin-token-change-me-32-bytes" }
Invoke-RestMethod http://127.0.0.1:8080/v1/agents -Headers $headers
Invoke-RestMethod http://127.0.0.1:8080/v1/alerts -Headers $headers
```

假设待保护业务监听 `127.0.0.1:9000`，先以观察模式启动 Gateway：

```powershell
go run ./cmd/mysafe-gateway `
  --upstream http://127.0.0.1:9000 `
  --address 127.0.0.1:8081 `
  --mode observe `
  --failure-policy fail_open
```

业务流量改为经过 `127.0.0.1:8081`。观察并调优正常流量后，再把模式切换为 `block`；不要在未知业务流量上直接开启拦截。

### PostgreSQL / MySQL

控制面必须显式选择存储，不会从数据库错误悄悄回退到内存：

```text
mysafe-control --store postgres --database-dsn "postgres://user:password@host:5432/mysafe?sslmode=verify-full"
mysafe-control --store mysql --database-dsn "user:password@tcp(host:3306)/mysafe"
```

启动时默认应用嵌入式、幂等迁移。开发数据库示例位于 `deploy/compose.yaml`；生产环境应使用独立凭据、TLS、备份和受限网络，而不是示例密码。

### 验证与构建

```text
go test -race ./...
go vet ./...
```

Linux 发布构建可在 Bash 环境执行 `scripts/build.sh`，生成 Agent、Control Plane、Gateway 和 Installer 的 amd64/arm64 二进制；存在 `dpkg-deb` 时同时生成 8 个 `.deb`。全部产物进入 schema v2 签名清单和 `SHA256SUMS`。tag 任务会自验 Ed25519 清单、运行本地镜像 Bootstrap dry-run，再发布产物和构建证明。安装器记录当前版本，默认拒绝签名降级，升级失败/显式 rollback 会恢复旧二进制、配置和版本状态。

CI 的兼容任务会在 Ubuntu 22.04/24.04 hosted runner 与 Debian 12/13 容器上运行环境探测和完整构建；Debian 任务还会实际 `dpkg -i` 四个 amd64 组件包。PostgreSQL 18 和 MySQL 8.4 继续运行同一数据库契约。

主要目录：

```text
cmd/                    Agent、Control、Gateway、Installer、Release 命令
internal/agent/         身份、加密队列、控制面客户端与运行循环
internal/control/       Headless HTTP API 与鉴权
internal/gateway/       Coraza/OWASP CRS 反向代理
internal/store/         内存与 PostgreSQL/MySQL Repository
internal/scanner/       只读主机清单扫描
api/openapi.yaml        OpenAPI 3.1 契约
deploy/                 systemd、环境示例与开发数据库
scripts/                构建和 Ubuntu Agent 安装脚本
scripts/package-deb.sh  Agent/Control/Gateway/Installer Debian 组件包
docs/                   兼容矩阵与交付文档
```

### 当前安全边界与未完成范围

- 非回环控制面地址只允许 HTTPS；生产模式可由 Control 生成独立 Agent CA，注册后同时校验设备 Token 和 SPIFFE URI SAN mTLS 证书，并在到期前自动轮换。证书吊销列表、OIDC 管理身份和 gRPC 尚未实现。
- Bootstrap Token 只用于首次注册，设备凭据只返回一次；安装成功后应立即吊销或轮换 Bootstrap Token。
- Agent 队列使用本机随机 256 位密钥加密，状态目录权限为 `0700`，但完整的硬件密钥封装与密钥轮换仍属于后续加固。
- Gateway 不信任客户端自带的 `X-Forwarded-*`。规则命中已通过本地 outbox/Unix socket 回传 Agent；受信代理 CIDR、GeoIP 和限流仍待实现，完整 Unix 权限链路待 Linux CI/实机认证。
- 文件轮询基线、SSH 爆破/可疑成功、进程身份与 TCP 监听变化检测已实现；inotify 加速、journalctl/hidepid 真实主机认证、异常外联、隔离区、签名处置/升级、100 个检测场景和 Flutter App 尚未完成。
- Flutter App 属于 UI 阶段；按项目流程，必须先逐屏生成位图预览并由用户确认，之后才会实现界面和审批链路。
- 当前版本适合继续开发、测试和安全评审，不应在未完成威胁建模、压力测试、第三方审计和灰度验证前宣称“检测所有攻击”或直接用于关键生产系统。

## 1. 项目目标

My Safe 的目标不是再造一个沉重的企业安全平台，而是提供一个轻量、好部署、容易嵌入现有项目的服务器安全系统。

它应当能够：

- 以很小的改动接入所有暴露在公网的项目；
- 检测并阻断 SQL 注入、XSS、命令注入、路径穿越、恶意上传等常见攻击；
- 监控服务器文件、Nginx、SSH、进程、端口、登录日志和系统配置；
- 发现 WebShell、未知后缀文件、双后缀文件和配置篡改；
- 支持国家或地区级 IP 访问控制；
- 通过手机 App 实时告警、查看证据、调整策略和审批应急操作；
- 对外提供 REST API、gRPC 和 Webhook，供其他项目后台接入；
- 不提供 Web 管理页面，所有可视化操作集中在 App；
- 支持 MySQL 和 PostgreSQL 两种数据库；
- 支持 Ubuntu 环境扫描、周期扫描和 24 小时实时监控；
- 支持 GitHub Actions 构建、签名和部署；
- 在重大事件中执行封禁、隔离、回滚、网络隔离等安全动作；
- 保持低资源占用，并且不会因为控制服务暂时离线而影响业务运行。

安全系统不存在“检测所有攻击”或“绝对无侵入”的保证。本项目的设计目标是通过分层防御、可验证规则、低误报策略和安全的自动处置，在轻量与防护能力之间取得平衡。

## 2. 总体架构

```mermaid
flowchart LR
    Internet["公网流量"] --> Nginx["Nginx"]
    Nginx --> Gateway["My Safe Gateway\n关闭 / 观察 / 拦截"]
    Gateway --> Apps["Go / Java / PHP / Node 等业务项目"]

    Agent["My Safe Agent\n文件 / SSH / 进程 / 端口 / 日志探针"] --> Queue["本地加密事件队列"]
    Gateway --> Queue
    Queue -->|"mTLS 出站连接"| Core["Headless Go Control Plane\n不提供 Web 页面"]

    Core --> DB["MySQL / PostgreSQL"]
    Core --> Push["APNs / FCM"]
    Push --> App["My Safe 手机 App"]
    App -->|"查看、审批、策略调整"| Core
    External["其他项目后台"] -->|"OpenAPI / Webhook"| Core
    Core -->|"签名、限权、可审计任务"| Agent
```

系统分为四个核心部分：

1. **Agent**：安装在每台 Ubuntu 服务器上的轻量 Go 常驻程序；
2. **Gateway/BFF/WAF**：可开关的流量安全中间层；
3. **Control Plane**：无 Web 页面的 Go 控制服务，负责资产、策略、告警和审计；
4. **App**：iOS/Android 可视化客户端，负责实时告警与安全操作审批。

## 3. Agent 是什么

Agent 不是 AI Agent，也不是网页后台，而是安装在每台服务器上的“小型安全守卫程序”，例如：

```text
/usr/local/bin/my-safe-agent
```

它由 systemd 管理，开机自动运行。主要职责包括：

- 监控 Nginx、SSH、系统登录和安全日志；
- 监控网站目录、配置目录和关键系统文件；
- 检查端口、异常进程、反弹 Shell、挖矿程序和异常外联；
- 发现 SSH 公钥、`sshd_config`、sudoers、cron 和 systemd 配置变化；
- 执行首次环境扫描和周期扫描；
- 将告警通过 mTLS 加密发送给控制服务；
- 控制服务离线时，将事件写入本地加密队列，恢复后续传；
- 在策略允许或用户批准后，执行封 IP、隔离文件、回滚配置或隔离服务器等动作。

Agent 与 WAF 的区别可以概括为：

- WAF 是门卫，在请求进入业务前检查攻击；
- Agent 是服务器内部全天巡逻的保安，检查文件、进程、SSH、日志和配置；
- Control Plane 是没有网页的控制中心；
- App 是可视化、审批和应急入口。

例如攻击者上传 `image.jpg.php` 时：

1. WAF 在上传请求阶段尝试阻断；
2. 如果文件仍然落盘，Agent 检测双后缀、真实文件类型和异常内容；
3. Agent 将文件移动到隔离区，计算哈希并保存必要证据；
4. App 收到实时告警；
5. 用户可在 App 中确认删除、封禁来源 IP 或检查同目录文件。

## 4. 轻量化设计

基础安装只包含一个 Go Agent 和按需启用的 Gateway，不默认捆绑 Elasticsearch、Kafka、完整 SIEM 或大型容器平台。

设计目标：

- Agent 空闲内存目标不超过 60 MB；
- Agent 空闲 CPU 目标低于 1%；
- 高流量原始请求不全部写入数据库；
- 默认不保存完整 Cookie、Authorization、密码和请求正文；
- 请求证据先脱敏，再按策略保留摘要；
- 大量低风险事件在 Agent 侧聚合后上报；
- 高级 eBPF/Falco 运行时检测作为可选扩展包，不进入基础安装；
- 请求体检查设置大小上限，超出部分按策略拒绝、跳过或落临时文件；
- 真实延迟和吞吐必须使用目标项目流量压测，不承诺脱离环境的固定数字。

## 5. 三种接入模式

| 模式 | 项目改动 | 能力 | 适用场景 |
|---|---:|---|---|
| Sensor | 几乎零改动 | 主机、文件、SSH、日志、进程检测；不能在请求到达前阻断 | 暂时不能改流量链路的项目 |
| Nginx/Gateway | 增加一段 `include` 配置 | 完整 WAF、限流、IP/地区封禁、恶意上传检查 | 默认推荐模式 |
| SDK Middleware | Go 项目注册一个中间件 | WAF + 用户、租户、资源和业务上下文 | 重要 API 和核心业务 |

建议的统一配置：

```yaml
integration: nginx       # sensor | nginx | sdk

bff:
  enabled: true
  mode: observe          # bypass | observe | block

failure_policy: fail_open # fail_open | fail_closed
```

### BFF/WAF 开关

- `bypass`：不检查流量，仅保留健康检查；
- `observe`：检测并告警，但不拦截；
- `block`：对满足阻断条件的请求执行拒绝、限流或挑战；
- `fail_open`：安全网关异常时放行业务流量，优先保证可用性；
- `fail_closed`：安全网关异常时拒绝流量，仅适合少数高安全场景。

新项目接入后建议先运行 3～7 天 `observe`，收集正常流量并调整例外规则，再逐步启用 `block`。

完全不改变流量链路时，系统可以检测主机与日志异常，但不能保证在恶意 HTTP 请求进入应用前完成阻断。因此“绝对无侵入”和“请求前阻断”无法同时成立。

## 6. Web 防护方案

Gateway 使用 Go 实现，集成 Coraza WAF 和 OWASP Core Rule Set（CRS）。重点能力包括：

- SQL 注入；
- XSS；
- 命令注入和远程代码执行特征；
- 本地/远程文件包含；
- 路径穿越；
- SSRF；
- XXE；
- 服务端模板注入；
- CRLF 和响应拆分；
- 异常协议与请求头；
- 恶意文件上传；
- 扫描器与自动化攻击特征；
- 按 IP、账号、接口和设备维度限流；
- 自定义虚拟补丁规则。

Coraza 可以直接包装 Go `http.Handler`，CRS 也能以 Go 包方式嵌入。参考：

- [Coraza Go HTTP 集成](https://www.coraza.io/docs/reference/internals/)
- [Coraza 与 OWASP CRS](https://www.coraza.io/docs/tutorials/coreruleset/)
- [OWASP CRS 文档](https://coreruleset.org/docs/)

WAF 不能理解所有业务授权。比如 BOLA/IDOR 必须知道“当前用户是否拥有当前对象”，因此核心 API 需要通过 SDK 传入用户、租户、角色和资源上下文。参考：[OWASP API1:2023 BOLA](https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/)。

## 7. 100 个攻击检测场景

“支持 100 种攻击”应定义为 100 个可测试、可验收的检测场景，而不是随意编写 100 条正则表达式。

| 检测包 | 场景数量 | 代表能力 |
|---|---:|---|
| Web 协议与注入 | 28 | SQLi、XSS、RCE、命令注入、SSTI、XXE、SSRF、CRLF、LFI/RFI、路径穿越、反序列化、异常协议 |
| API 与身份攻击 | 18 | 暴力破解、撞库、密码喷洒、Token 重放、JWT 异常、接口枚举、GraphQL 资源滥用 |
| 文件与上传 | 16 | WebShell、双后缀、MIME 伪造、ELF 落入 Web 目录、`.env` 泄露、恶意脚本和配置篡改 |
| 主机运行时 | 16 | 反弹 Shell、挖矿、异常子进程、提权、SUID 变化、cron/systemd 持久化、日志删除 |
| 网络与 SSH | 12 | 端口扫描、SSH 爆破、root 登录、新增公钥、sshd 弱化、异常外联和 DNS 异常 |
| 可用性与供应链 | 10 | L7 洪泛、资源耗尽、未知软件包、镜像变化、规则或升级签名失败 |
| **总计** | **100** | 第一版验收目录 |

每个检测场景必须包含：

- 场景编号和攻击说明；
- 可重复的测试样本；
- 正常流量反例；
- 触发条件和置信度；
- 严重度和默认动作；
- 允许的例外配置；
- 自动处置与回滚方式；
- 单元测试、集成测试和误报回归测试。

当前 OWASP Web 风险基线为 Top 10:2025，其中包括注入、软件或数据完整性、安全日志与告警等核心风险。参考：[OWASP Top 10:2025](https://owasp.org/Top10/2025/0x00_2025-Introduction/)。

## 8. 环境扫描与持续监控

### 8.1 首次安装扫描

首次安装只扫描和给出建议，不直接修改生产环境：

- Ubuntu 版本、内核版本、安全更新和软件包状态；
- 公网监听端口、防火墙和路由规则；
- Nginx、TLS、站点配置和代理链；
- MySQL/PostgreSQL 是否意外暴露公网；
- Docker/容器和镜像信息；
- SSH 配置、root 登录、密码登录、登录历史和 authorized_keys；
- 用户、用户组、sudoers 和异常高权限账号；
- cron、systemd、启动脚本和持久化入口；
- SUID/SGID 文件；
- Web 目录、配置目录、证书和密钥文件权限；
- `.env`、备份文件、数据库导出等敏感文件暴露；
- 异常进程、监听端口和外联目标；
- 关键文件哈希和初始完整性基线。

扫描完成后生成风险报告，并让用户选择：忽略、修复建议、立即处理或加入计划任务。

### 8.2 推荐扫描周期

| 项目 | 周期 |
|---|---:|
| 文件、登录、进程、关键配置变化 | 实时 |
| Nginx 与 SSH 配置 | 实时 |
| 端口与公网暴露变化 | 每 5 分钟 |
| 主机状态和资源异常 | 每 1 分钟聚合 |
| 软件包及 CVE 差异 | 每天 |
| 全量完整性扫描 | 每周 |
| 检测规则更新检查 | 每 6 小时 |

扫描任务要支持随机抖动和资源上限，避免所有服务器同时扫描导致 CPU 或磁盘峰值。

## 9. Nginx 篡改保护

Agent 对 `/etc/nginx`、站点配置和证书引用建立基线：

- 记录文件哈希、权限、属主和最后修改信息；
- 监控配置文件新增、删除和修改；
- 记录触发修改的进程和用户；
- 修改前后生成差异；
- 自动操作前创建备份；
- 使用 `nginx -t` 进行语法验证；
- 通过后才平滑 reload；
- 验证失败时保留旧配置并告警；
- 高风险修改可自动恢复到签名基线。

Nginx 官方说明在 reload 前会验证新配置，失败时继续使用旧配置。参考：[Controlling nginx](https://nginx.org/en/docs/control.html)。

自动回滚只能针对系统明确管理的配置目录，不能覆盖未知的人工变更；部署窗口内的合法修改应通过签名变更单或临时维护模式放行。

## 10. 可疑文件与恶意上传

文件探针不能只检查后缀，应综合判断：

- 双后缀或多重后缀；
- 扩展名与 MIME/文件魔数不一致；
- Web 目录出现 ELF、Shell、PHP、JSP 或其他可执行内容；
- 图片、压缩包或文档中嵌入异常脚本；
- 高熵混淆内容；
- 常见 WebShell、反弹 Shell 和加载器特征；
- 文件落盘后被快速改名或修改；
- 上传目录中新建可执行权限文件；
- 与部署清单不一致的新增文件。

默认处置是隔离而不是删除：

1. 移动到不可执行隔离目录；
2. 计算 SHA-256；
3. 保存属主、权限、来源进程和时间；
4. 对敏感内容脱敏；
5. 上报告警；
6. 由策略或 App 审批决定恢复或删除。

## 11. 地区和 IP 访问控制

系统支持：

- 国家/地区级允许或拒绝；
- CIDR 网段；
- 单 IP 临时或永久封禁；
- 按项目、域名、API 路径设置不同策略；
- 自动封禁时设置 TTL；
- App 内快速解除误封；
- nftables 集合进行 L3/L4 封禁；
- Gateway/Coraza 进行 L7 规则控制。

Coraza 提供官方 GeoIP 插件。参考：[Coraza Plugins](https://www.coraza.io/docs/tutorials/using-plugins/)。

若项目位于 CDN、负载均衡或反向代理后方，只有来自可信代理网段的真实 IP 请求头才可以使用，否则攻击者可能伪造 `X-Forwarded-For`。地区识别也可能被 VPN、代理和移动网络影响，所以默认适合限流、增强验证或观察，不建议对高价值合法用户直接永久封禁。

## 12. SSH 密钥和访问方案

不建议让 App 查看、下载或同步服务器私钥。私钥进入 App、数据库或推送链路后，一处泄露可能导致所有服务器失守。

推荐使用 SSH CA 和短期证书：

1. 手机在系统安全硬件中生成私钥，私钥不可导出；
2. 用户通过指纹或 Face ID 验证；
3. App 向 SSH CA 申请 5～15 分钟的用户证书；
4. 服务器只信任 CA 公钥；
5. 证书到期自动失效；
6. 禁用用户或设备后不再签发新证书；
7. 服务器主机密钥按 30～90 天轮换，并保留新旧密钥重叠窗口；
8. 所有签发和登录行为进入审计日志。

可选实现为开源 `step-ca`。参考：

- [step-ca](https://smallstep.com/docs/step-ca/)
- [SSH Certificate Login](https://smallstep.com/docs/tutorials/ssh-certificate-login/)

对于暂时不能改造 SSH CA 的环境，Agent 可以管理 `authorized_keys` 的签名清单、过期时间和审批流程，但仍然不允许 App 获取服务器私钥。

## 13. App 功能

App 建议采用 Flutter，同时支持 iOS 和 Android。

核心页面：

- 服务器与项目列表；
- 在线状态、Agent 版本、风险等级和最近扫描；
- 实时告警；
- 事件时间线和脱敏证据；
- 攻击来源 IP、地区、接口和命中规则；
- 文件变更差异和隔离区；
- Nginx、SSH、端口和进程异常；
- 策略与例外规则；
- IP/地区封禁；
- SSH 短期授权；
- 应急处置审批；
- 操作审计和回滚。

重大告警应显示：

- 哪台服务器、哪个项目受影响；
- 发生了什么；
- 来源和目标；
- 置信度与严重度；
- 系统已经采取的动作；
- 关键脱敏证据；
- 推荐下一步；
- 可执行动作和预计影响。

App 使用设备绑定、短期访问令牌、生物识别和高风险操作二次确认。多人团队支持双人审批；单人使用时采用二次确认、长按确认和短时授权。

## 14. 自动处置等级

自动处置必须避免成为攻击者制造 DoS 的工具。

| 等级 | 动作 | 默认策略 |
|---|---|---|
| L0 | 记录、关联、推送通知 | 自动 |
| L1 | 限流、临时封 IP、终止恶意会话 | 高置信事件自动 |
| L2 | 隔离文件、阻断路由、暂停明确异常进程 | 策略允许或 App 审批 |
| L3 | 网络隔离，仅保留控制面、SSH 救援和取证通道 | 强确认或预授权策略 |
| L4 | 操作系统关机或云主机停止 | 默认关闭，最高风险审批 |

不允许 App 提供任意命令输入框，因为这相当于给所有服务器增加一个远程命令执行控制面。替代方案是签名的白名单处置剧本：

- 临时封禁指定 IP；
- 隔离指定文件；
- 停止明确指定的服务；
- 回滚 Nginx 配置；
- 禁用指定 SSH 用户；
- 关闭公网入口；
- 进入网络隔离；
- 创建云磁盘快照；
- 停止云主机。

每个任务必须包含：任务 ID、服务器、允许的参数、发起者、审批者、有效期、签名、执行结果、回滚信息和完整审计记录。

自动关机默认关闭。更安全的重大事件流程是：先阻断攻击流量，再保存证据和快照，然后隔离网络，最后由用户判断是否停止主机。直接关机会丢失内存证据，也可能被攻击者利用为远程拒绝服务。

## 15. Agent 自身安全

安全 Agent 本身必须按高风险软件设计：

- 主进程以普通用户运行；
- 特权操作由单独的最小权限 helper 执行；
- Agent 与 helper 通过受限 Unix Socket 通信；
- helper 只接受结构化白名单任务，不接受 Shell 字符串；
- 所有任务验证签名、时间戳、防重放 nonce 和目标服务器 ID；
- Agent 与控制面使用双向 TLS；
- 本地队列和敏感配置加密；
- systemd 启用最小权限和文件系统保护；
- 日志禁止输出 Token、密钥、Cookie 和密码；
- 更新包、规则包和处置剧本必须签名；
- 支持版本固定、灰度升级、健康检查和自动回滚；
- 控制面失陷时，可以通过服务器本地策略拒绝超出范围的任务。

## 16. 控制服务与双数据库

控制服务使用 Go，实现为 Headless API 服务，不打包任何 HTML、模板或 Web 静态资源。

数据库支持：

- MySQL；
- PostgreSQL。

建议通过统一 Repository 层和数据库方言适配实现，CI 中对两种数据库运行相同迁移和集成测试。

核心数据模型：

- tenants；
- users；
- devices；
- servers；
- agents；
- projects；
- policies；
- detectors；
- alerts；
- incidents；
- evidence；
- actions；
- approvals；
- ssh_certificate_requests；
- audit_logs；
- update_rollouts。

数据库只存资产、策略、告警、事件、审计和汇总。高频原始请求不直接全部入库；Agent 侧先过滤、脱敏、聚合和采样，避免数据库成为性能瓶颈或敏感数据仓库。

## 17. 对外 API

虽然产品没有 Web 管理页面，但必须具备完整 API：

- REST / OpenAPI 3.1：供 App 和第三方后台使用；
- gRPC + mTLS：供 Agent 与控制面通信；
- 签名 Webhook：推送告警和事件状态；
- OAuth/OIDC 或短期 Token：第三方身份认证；
- 基于 scope 的最小权限授权；
- 幂等键和防重放机制；
- API 限流和审计。

示例资源：

```text
/v1/servers
/v1/projects
/v1/alerts
/v1/incidents
/v1/policies
/v1/actions
/v1/approvals
/v1/quarantine
/v1/ssh/certificates
/v1/webhooks
```

## 18. GitHub 构建与一键部署

首次部署不能在没有任何服务器凭据或预装组件的情况下真正做到“远程一键”。推荐模式是：首次执行一条经过验证的安装命令，后续即可通过 GitHub Actions 或 App 完成升级与管理。

发布流程：

1. GitHub Actions 编译 Go 静态二进制；
2. 生成 Ubuntu `.deb` 和压缩包；
3. 生成 SHA-256、SBOM 和构建证明；
4. 对 Agent、规则包和安装脚本签名；
5. 安装器固定版本并验证签名；
6. 使用一次性、短时注册 Token 绑定服务器；
7. 安装 systemd 服务和最小权限配置；
8. 首次运行环境扫描；
9. 默认进入 observe 模式；
10. 后续由 Agent 主动拉取签名更新，不在 GitHub 长期保存服务器 SSH 私钥。

升级采用 5% → 25% → 100% 灰度策略。健康检查、Agent 心跳或错误率异常时停止扩散并回滚。

GitHub Actions 可使用环境审批、OIDC 短期凭据和构建证明：

- [GitHub Artifact Attestations](https://docs.github.com/en/actions/how-tos/secure-your-work/use-artifact-attestations/use-artifact-attestations)
- [GitHub Actions OIDC](https://docs.github.com/en/actions/reference/security/oidc)
- [GitHub Deployment Environments](https://docs.github.com/en/actions/reference/workflows-and-actions/deployments-and-environments)

## 19. 告警、证据与隐私

告警等级：

- Info：资产或配置变化；
- Low：低风险异常；
- Medium：需要关注但尚无明确攻击证据；
- High：高概率攻击或重要配置篡改；
- Critical：已确认入侵、持久化、数据风险或大范围影响。

证据最小化原则：

- 默认不记录完整 Authorization、Cookie、密码和表单敏感字段；
- 请求正文按字段策略脱敏；
- 文件只上传哈希、元数据和必要片段；
- 完整取证包需额外审批；
- 数据设置自动过期时间；
- 所有查看、导出和删除操作进入审计；
- 支持按项目和数据类型配置保留周期。

## 20. 可靠性与故障模式

- 控制服务离线：Agent 继续按最后一次有效策略运行并缓存事件；
- 数据库离线：控制服务进入降级模式，告警暂存队列；
- Gateway 异常：按项目选择 fail-open 或 fail-closed；
- 规则更新失败：继续使用上一个签名有效版本；
- Agent 升级失败：自动恢复上一版本；
- Nginx 配置失败：保留旧配置，不 reload；
- App 推送失败：事件仍保存在控制面，恢复后可查看；
- 网络隔离：必须保留预先定义的救援与控制通道；
- 时钟异常：任务签名校验失败并告警，防止过期任务被执行。

## 21. 开发计划与时间预估

完整范围达到可用于生产的第一版，预计需要 8～12 周；能安装、能检测、能拦截、能在 App 查看告警的 MVP，预计 2～3 周。

| 阶段 | 预计时间 | 交付内容 |
|---|---:|---|
| 可运行原型 | 3～5 天 | Go Agent、控制服务、双数据库、基础扫描、API |
| MVP | 2～3 周 | Nginx/WAF、注入防护、文件篡改、SSH 日志、App 告警、Ubuntu 安装脚本 |
| 内测版 | 4～6 周 | 地区封禁、隔离文件、策略下发、自动封 IP、审计、GitHub 部署 |
| 生产 Beta | 8～12 周 | SSH 短期证书、签名升级、100 场景及测试、故障回滚、性能与安全加固 |
| 成熟稳定版 | 3～6 个月持续迭代 | 误报调优、更多环境、威胁情报、规则更新和第三方安全审计 |

### 第一阶段：第 1 周

- 建立 Go Monorepo；
- Agent 注册、心跳和 mTLS；
- MySQL/PostgreSQL Repository；
- 数据库迁移；
- Headless REST/gRPC API；
- Ubuntu 环境扫描；
- 本地事件队列；
- systemd 安装脚本。

### 第二阶段：第 2 周

- Coraza + OWASP CRS；
- Nginx/Gateway 接入；
- observe/block 模式；
- 文件完整性和隔离区；
- SSH 与异常登录监控；
- IP 限流和临时封禁。

### 第三阶段：第 3 周

- Flutter App 基础功能；
- 推送告警；
- 事件详情和策略；
- App 审批动作；
- GitHub Actions 构建；
- 签名安装和升级；
- MVP 部署与文档。

### 第四阶段：第 4～6 周

- Nginx 篡改保护；
- 地区封禁；
- 进程、端口、持久化检测；
- 自动处置等级；
- 审计与回滚；
- 双数据库完整集成测试；
- 多服务器灰度升级。

### 第五阶段：第 7～12 周

- SSH CA 和短期证书；
- 完成 100 个检测场景；
- 攻击回归和误报测试；
- 性能、压力、故障和安全测试；
- 高风险操作双重确认；
- 可选 eBPF/Falco 扩展；
- 生产 Beta 发布。

## 22. MVP 验收标准

第一版 MVP 至少满足：

- Ubuntu 22.04/24.04 可通过安装脚本部署；
- Agent 可注册、心跳、断线缓存和恢复续传；
- MySQL/PostgreSQL 通过相同业务测试；
- Nginx 模式支持 bypass/observe/block；
- 能检测并阻断基础 SQLi、XSS、路径穿越和恶意上传；
- 能发现 Nginx、SSH 和 Web 目录关键变化；
- 能检测 SSH 爆破和异常登录；
- 能通过 App 收到严重告警；
- 能从 App 审批临时封 IP 和隔离文件；
- 所有动作可审计；
- 不在日志、数据库和推送中泄露密钥、Token 或密码；
- 控制服务或数据库短时离线不影响受保护业务；
- 更新包和规则包必须通过签名验证；
- 升级失败能够回滚。

## 23. 必须坚持的安全边界

以下原则不能为了“方便”而取消：

- App 不显示、下载或保存服务器 SSH 私钥；
- App 不提供任意远程 Shell 命令；
- 自动关机默认关闭；
- 可疑文件默认隔离，不直接删除；
- Nginx 修改必须先备份并验证；
- 新规则先 observe，再逐步 block；
- 所有特权任务白名单化、签名化、短时化和可审计；
- Agent 不以无限 root 权限运行；
- 推送通知不包含敏感请求正文；
- 控制面失陷不能直接等价于服务器 root 权限；
- 任何“自动修复”都必须明确影响范围和回滚路径。

## 24. 后续方向

- 多租户和组织权限；
- 云厂商安全组、快照和实例隔离；
- CrowdSec 威胁情报可选连接器；
- Falco/eBPF 高级运行时探针；
- Kubernetes 节点和 Ingress 模式；
- 更多语言 SDK；
- 规则签名与社区规则仓库；
- 与现有 SIEM、工单和告警平台对接；
- 自动生成事件报告与复盘材料；
- 第三方渗透测试和安全审计。

## 25. 结论

My Safe 最合适的产品形态是“轻量 Agent + 可选安全 Gateway + Headless 控制服务 + 手机 App”，而不是单一插件或大型后台。

它通过三种接入模式兼顾低改动与强防护，通过 Coraza/OWASP CRS、文件完整性、SSH 与运行时监控覆盖 Web 和主机风险，通过短期 SSH 证书代替私钥分发，并使用分级自动处置避免安全系统本身成为远程 DoS 或 RCE 工具。

现实的交付节奏是：3～5 天得到可运行原型，2～3 周得到可部署 MVP，8～12 周达到生产 Beta，随后持续进行规则更新、误报优化和安全审计。
