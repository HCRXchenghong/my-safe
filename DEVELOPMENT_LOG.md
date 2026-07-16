# 开发日志

## 2026-07-16 15:48 +08:00

- 步骤：拉取并审计远端仓库，恢复项目上下文，完成第一轮技术栈调研。
- 文件变更：从 `main` 分支源码归档恢复 `README.md`；新增项目过程记录。
- 命令/检查：`git clone`、`git ls-remote`、GitHub codeload 下载、`rg --files`、Go/PostgreSQL/MySQL 官方版本页面检查、`go version`。
- 结果：远端仓库仅包含产品规格 README；GitHub Git 端点连接重置，改用 codeload 成功获取源码。确认本机 Go 1.26.3，官方当前稳定版 Go 1.26.5；Docker 未安装。
- 下一步：完成可运行核心原型的领域模型、控制面 API 与存储边界。

## 2026-07-16 16:05 +08:00

- 步骤：完成控制面与 Agent 核心闭环。
- 文件变更：新增领域模型、脱敏、内存 Store、控制面 API、Agent 身份、AES-256-GCM 队列、只读扫描器、客户端、两个命令和端到端测试。
- 命令/检查：`go test ./internal/...`、Agent/控制面 `httptest` 真实链路。
- 结果：注册、心跳、凭据重启恢复、事件幂等、离线保留与恢复续传全部通过；控制面不会回显凭据哈希。
- 下一步：双数据库、交付骨架与 Gateway。

## 2026-07-16 16:33 +08:00

- 步骤：完成双数据库适配、部署骨架和 Coraza/OWASP CRS Gateway。
- 文件变更：新增 PostgreSQL/MySQL SQLStore 与迁移、OpenAPI、CI、systemd、Compose、构建/安装脚本、Gateway 三模式实现及测试；更新 README。
- 命令/检查：`go mod tidy`、`go test -race ./...`、`go vet ./...`、Linux amd64/arm64 交叉构建、YAML/Bash 解析测试、SQLi/XSS/路径穿越代理测试。
- 结果：race 与 vet 全通过；Agent、Control、Gateway 共 6 个 Linux amd64/arm64 二进制交叉构建成功；三类攻击在 block 模式均返回 403 且未到达上游，observe 模式记录命中并放行。
- 下一步：在真实 PostgreSQL/MySQL CI 服务确认契约；实现持续文件/SSH 探针、网关事件回传与 mTLS；进入 App 前先审批 UI 位图预览。

## 2026-07-16 16:44 +08:00

- 步骤：启动通用一键部署与兼容性阶段，恢复全部项目记录并调研当前官方支持矩阵。
- 文件变更：更新项目最终交付定义、兼容边界、签名供应链与回滚决策。
- 命令/检查：读取全部 Markdown；检查 Git 状态；查询 Ubuntu LTS、Debian Releases、Docker Engine、Nginx、systemd、GitHub Attestations 和 Go Ed25519 官方资料。
- 结果：稳定目标锁定 Ubuntu 22.04/24.04、Debian 12/13、amd64/arm64、systemd；Ubuntu 26.04 暂列实验。自动接入必须采取 Sensor 保底、Gateway 有条件增强。
- 下一步：实现环境探测、兼容性评分、签名清单和事务式安装计划。

## 2026-07-16 17:54 +08:00

- 步骤：关闭通用部署核心链路并验证新 Bootstrap/Release 流程。
- 文件变更：完成环境探测、签名 release bundle、事务安装/回滚、Nginx 条件接入、Installer/Release CLI；修复 Bootstrap 版本绑定和临时目录清理；修复 tag glob；发布任务新增本地镜像端到端 dry-run；新增兼容矩阵并更新 README。
- 命令/检查：`go test ./internal/spec ./internal/releasebundle ./internal/installer`、`go test ./...`、`go vet ./...`、Git Bash `bash -n`、OpenSSL 3 Ed25519 验签、`actionlint`。
- 结果：全部本机验证通过；篡改、错误签名/哈希/版本在事务前拒绝，安装/Nginx 故障自动回滚，短时 Bootstrap Token 不落盘。真实 Ubuntu/Debian systemd 主机和 tag hosted runner 尚未执行，因此不宣称生产完成。
- 下一步：实现文件完整性、SSH 认证和进程/端口变化检测，并通过 Agent 加密队列真实上报。

## 2026-07-16 18:06 +08:00

- 步骤：完成文件完整性轮询基线及真实上报链路。
- 文件变更：新增 `internal/detector/fileintegrity`，Agent 增加默认 Linux 关键路径、可配置 watch roots 和显式禁用开关；新增基线代次、原子提交、覆盖受限与批量变化事件；补充端到端集成测试和文档。
- 命令/检查：`go test ./internal/detector/fileintegrity ./internal/agent ./internal/integration -v`、对应 `go test -race` 与 `go vet`。
- 结果：首次只建基线；创建、修改、删除均产生最小化事件；文件正文不会进入事件；事件先入加密队列后才推进基线；失败重试幂等；损坏基线拒绝覆盖；全部检查通过。
- 下一步：实现 SSH 成功/失败认证日志增量读取、爆破窗口聚合和日志轮转游标恢复。

## 2026-07-16 18:20 +08:00

- 步骤：完成 SSH 认证、爆破聚合和 systemd journal 保底源。
- 文件变更：新增 `internal/detector/sshauth`；Agent 增加 auth.log/secure 路径配置和默认启用；systemd 单元补充最小日志读取组；实现文件偏移/前缀轮转检测、journal cursor、滑动窗口、告警抑制与失败后成功升级。
- 命令/检查：SSH 解析/游标/轮转/半行/IPv6/journal fake 单元测试，Agent → 加密队列 → Control Plane 端到端测试，对应 `go test -race` 与 `go vet`。
- 结果：低频失败不逐条告警；同源达到阈值产生一次高危事件；三次以上失败后的成功登录产生高危可疑成功；首次安装不回放历史；原始日志行不上传；全部自动化检查通过。真实 journalctl/logrotate 主机认证仍待兼容矩阵执行。
- 下一步：实现进程与监听端口持久化基线，识别新增监听、进程二进制漂移和敏感进程变化。

## 2026-07-16 18:28 +08:00

- 步骤：完成进程身份与 TCP 监听变化基线。
- 文件变更：新增 `internal/detector/runtimewatch`；Agent 默认在 Linux 启用 procfs 检测；实现已知进程身份目录、同名身份漂移、tcp/tcp6 监听开关、地址范围分级、状态/文件/进程/端口上限和覆盖事件。
- 命令/检查：procfs 夹具单元测试、Agent → 加密队列 → Control Plane 端到端测试、对应 `go test -race` 与 `go vet`。
- 结果：PID 变化不重复告警；新 UID/可执行身份、同名身份漂移和端口变化可观察；wildcard/非回环新监听为高危；不读取进程命令行、环境变量或内存；全部自动化检查通过。
- 下一步：把 Gateway 规则命中通过本地受限通道交给 Agent，再上报控制面；随后进入 mTLS、策略和审计。

## 2026-07-16 19:03 +08:00

- 步骤：完成 Gateway 最小事件回传组件、Agent/Control mTLS 和策略/审计核心闭环。
- 文件变更：新增 `internal/localfeed`、`internal/gatewayevents`、`internal/mtls`；Gateway 增加无请求数据规则事件与离线 outbox；Agent 增加 Unix feed、mTLS CSR/证书/轮换和单调策略；Control 增加 Agent CA、双身份认证、证书轮换、策略与审计 API；双数据库新增 `002_policies_audit.sql`；更新 systemd/OpenAPI。
- 命令/检查：秘密不出端 WAF 测试、outbox 离线恢复、Unix schema/路径负例、真实 TLS 注册→mTLS→仅 Token 401→重启→轮换、策略 revision/审计/Agent 拉取、Linux 集成测试交叉编译、`go test -race ./...`、`go vet ./...`、`actionlint`。
- 结果：全部可在当前主机运行的检查通过；完整 Gateway Unix 路径因 Windows 环境未执行但 Linux 测试二进制已成功构建；PostgreSQL/MySQL 新契约等待 CI 服务。mTLS 客户端私钥不离开 Agent，CA 私钥不进入 API/数据库/发布包。
- 下一步：完成发布/真实系统兼容矩阵、`.deb` 与升级回滚；随后进入 UI 位图审批门。

## 2026-07-16 19:20 +08:00

- 步骤：完成 Debian 包定义、签名清单格式扩展、版本状态与 CI 兼容矩阵。
- 文件变更：release manifest 升级 schema v2 并区分 `binary`/`deb`；新增四组件双架构 `package-deb.sh`；安装器新增安装版本文件、SemVer 比较、降级保护和 rollback 验证；CI 新增 Ubuntu 22.04/24.04、Debian 12/13 构建/探测/包安装任务。
- 命令/检查：releasebundle/installer/spec 测试、Bash 解析、actionlint；Windows 重新构建 8 个 Linux 二进制并使用正式公钥对应本地私钥签名/验签 schema v2 bundle。
- 结果：本机全部检查通过；`dpkg-deb` 与 Docker 不可用，因此 8 个 `.deb` 的真实构建、Debian 安装和完整 Linux Unix socket 集成保留为 CI 待观察项，没有伪报为已通过。
- 下一步：进入 UI 位图预览审批；获批前不编写 Flutter 界面，同时后端剩余吊销、OIDC、特权动作和真实主机矩阵继续列为生产阻断项。

## 2026-07-16 19:21 +08:00

- 步骤：准备并发布 `v1.0.1`，将当前可运行后端、交付链路和兼容性工作推送至 GitHub。
- 文件变更：记录发布版本与验证边界；不纳入本地签名私钥、构建产物或运行状态。
- 命令/检查：`go test -race ./...`、`go vet ./...`、Bash 语法、`actionlint`、Linux amd64/arm64 二进制构建及 schema v2 清单签名/验签均已通过；提交前再次检查 Git 忽略项、敏感信息和远端标签。
- 结果：本地可执行验证全部通过；Ubuntu/Debian CI、真实 PostgreSQL/MySQL、`.deb` 构建安装及完整 Unix socket 链路仍以远端流水线结果为准，不将本版本描述为生产认证完成。
- 下一步：推送 `main` 和注解标签 `v1.0.1`，观察 CI 与签名发布任务；之后继续 UI 位图审批和生产阻断项实现。
