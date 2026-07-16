# My Safe 兼容性矩阵

更新时间：2026-07-16

My Safe 的“通用”是分层且可验证的：Sensor 是保底能力；只有能确定、验证并回滚流量拓扑时才自动启用 Gateway。安装成功不等于业务流量已经获得 WAF 保护。

## 平台矩阵

| 环境 | amd64 | arm64 | 当前等级 | 已完成验证 | 仍需验证 |
|---|---:|---:|---|---|---|
| Ubuntu 22.04 + systemd | 目标 | 目标 | 稳定目标 | OS/架构/计划夹具、交叉构建 | 两架构真实 VM 安装、重启、升级、回滚 |
| Ubuntu 24.04 + systemd | 目标 | 目标 | 稳定目标 | OS/架构/计划夹具、交叉构建 | 两架构真实 VM 安装、重启、升级、回滚 |
| Debian 12 + systemd | 目标 | 目标 | 稳定目标 | OS/架构/计划夹具、交叉构建 | 两架构真实 VM 安装、重启、升级、回滚 |
| Debian 13 + systemd | 目标 | 目标 | 稳定目标 | OS/架构/计划夹具、交叉构建 | 两架构真实 VM 安装、重启、升级、回滚 |
| Ubuntu 26.04 | 目标 | 目标 | 实验 | 识别并要求显式 `--allow-experimental` | 官方支持状态、依赖和实机全矩阵 |
| 其他 Linux / 非 systemd | 否 | 否 | 阻止自动安装 | 结构化 blocker 测试 | 在新增正式适配器前不支持 |

“稳定目标”表示实现边界已锁定，不表示真实主机认证已经完成。达到生产支持必须补齐表中真实 VM/主机检查。

## 项目与流量拓扑

| 项目形态 | Sensor | Gateway 自动接入 | 说明 |
|---|---:|---:|---|
| 任意语言的原生进程/systemd 服务 | 是 | 条件支持 | Agent 与业务语言无关；只有唯一 Nginx 回环上游时自动接入 |
| Nginx + 唯一字面量 `http://127.0.0.1:PORT` 或 `localhost` 上游 | 是 | 是 | Gateway 先健康检查，再改配置、`nginx -t`、reload；失败回滚 |
| Nginx 多 upstream、变量、Unix socket、动态服务发现 | 是 | 否 | 输出歧义原因，不猜测、不改流量 |
| Docker / Compose 项目 | 是 | 否（当前） | 能探测 Docker/Compose；当前不自动改容器网络或 Compose 文件 |
| Apache、Caddy、Traefik、HAProxy | 是 | 否（当前） | Sensor 可用；需要各自的显式、可回滚适配器 |
| Kubernetes / Ingress / Service Mesh | 节点安装未认证 | 否 | 不应把普通主机安装器冒充集群接入方案 |
| CDN、云负载均衡、Serverless | 取决于是否有受支持主机 | 否 | 需要边缘/云厂商适配器或手工拓扑 |

## 能力等级

- `Sensor`：Agent 已安装，可做主机扫描、轮询文件完整性、SSH auth.log/secure 增量游标、systemd journal cursor 保底、进程可执行身份目录、TCP 监听变化、加密离线队列和控制面上报。inotify 加速、异常外联和真实 hidepid 主机矩阵仍在开发/验证。
- `Gateway observe`：业务流量经过 Coraza/OWASP CRS，但规则只记录不拦截，用于误报基线。
- `Gateway block`：经过观察和审批后启用拦截。当前自动安装默认保持 `observe`。
- `Unsupported`：安装器明确阻止或退回 Sensor，并输出机器可读 blocker；绝不报告未发生的 WAF 接入。

## 一键接入边界

当前 `bootstrap.sh` 完成的是“已有 Control Plane 下的单台受保护主机接入”，不是从零创建数据库、Control Plane、域名和 TLS 的全平台托管器。它提供：

1. OS、架构、systemd、Nginx、Docker/Compose 和端口探测；
2. 固定 Ed25519 公钥、签名清单和每产物 SHA-256；
3. 当前架构产物下载；
4. Agent 保底安装；
5. 明确拓扑下的 Gateway 条件接入；
6. 事务日志、故障自动回滚和显式 rollback。

尚未完成的生产交付项包括 `.deb` 真实矩阵认证、签名自动升级、灰度发布、四发行版双架构真实主机认证、完整 Control Plane 首装编排、证书吊销/OIDC、特权动作审批执行以及第三方安全审计。mTLS、文件/SSH/进程/端口探针和策略持久化已进入自动化验证阶段，但仍需真实主机矩阵认证。

`.deb` 生成、内容检查和 Debian 12/13 amd64 实际安装已经进入 CI 定义；在首次 CI 成功结果出现前仍不把它计为已认证。arm64 当前是交叉构建/包构建目标，真实 arm64 VM 仍是发布阻断项。
