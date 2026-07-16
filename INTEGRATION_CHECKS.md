# 集成检查

## 功能：控制面健康与鉴权边界

- 验收：健康检查无需凭据；管理与 Agent 接口要求正确的短期/设备凭据；请求体有大小和字段限制。
- 命令/手工检查：待实现后运行 `go test ./...` 与端到端 HTTP 测试。
- 预期：合法请求成功，缺失或错误凭据返回 401，敏感值不出现在响应与日志中。
- 实际：`internal/control` 与 `internal/integration` 测试通过；错误凭据返回 401，事件证据在服务端递归脱敏。
- 状态：passed
- 后续：增加 OIDC 管理身份、设备凭据/证书吊销和速率限制；Agent mTLS 已通过。

## 功能：Agent 注册、心跳与事件续传

- 验收：Agent 使用引导令牌注册，后续使用设备凭据；控制面不可用时事件保持在本地加密队列，恢复后按幂等 ID 上传并删除本地副本。
- 命令/手工检查：单元测试队列重启恢复；端到端启动控制面和 Agent `--once`。
- 预期：注册、心跳、事件写入和告警查询形成真实 HTTP 闭环；队列文件不含明文事件内容。
- 实际：首次注册、凭据持久化、无 Bootstrap Token 重连、离线上报失败后队列深度保持 1、恢复后清空均通过；磁盘文件不含测试明文标记。
- 状态：passed
- 后续：密钥轮换、队列聚合与磁盘配额遥测。

## 功能：基础环境扫描

- 验收：在 Linux 读取 OS、内核、公开监听端口和关键配置存在性；在非 Linux 环境安全降级，不执行修改。
- 命令/手工检查：平台无关单元测试，Linux 构建检查。
- 预期：生成结构化、最小化且不含密钥正文的扫描事件。
- 实际：跨平台解析测试通过；Linux amd64/arm64 交叉构建通过。非 Linux 明确返回降级范围。
- 状态：passed
- 后续：在 Ubuntu 22.04/24.04 实机核对 `/proc`、权限和资源占用。

## 功能：构建与部署骨架

- 验收：Windows 当前环境测试通过；Linux amd64/arm64 二进制可交叉构建；systemd 单元采用普通用户和文件系统保护。
- 命令/手工检查：`go test ./...`、`go vet ./...`、`GOOS=linux GOARCH=amd64 go build ./cmd/...`。
- 预期：无编译、测试或 vet 错误。
- 实际：`go test -race ./...`、`go vet ./...`、Agent/Control/Gateway 共 6 个 Linux amd64/arm64 二进制交叉构建通过；systemd/YAML/Bash 已做语法检查，尚未在 Ubuntu 实机安装。
- 状态：pending
- 后续：Ubuntu 22.04/24.04 安装和 systemd 沙箱实机验收。

## 功能：PostgreSQL/MySQL 共享契约

- 验收：两种数据库应用各自迁移并通过相同的 Agent、心跳、幂等事件与查询契约。
- 命令/手工检查：设置 `MYSAFE_TEST_POSTGRES_DSN` 与 `MYSAFE_TEST_MYSQL_DSN` 后运行 `go test ./internal/store/sqlstore -v`；CI 已配置 PostgreSQL 18/MySQL 8.4 服务。
- 预期：两种方言均通过同一契约。
- 实际：本机无 Docker/数据库服务，解析、编译与跳过逻辑通过；真实双库结果等待 CI。
- 状态：pending
- 后续：推送后确认 CI 双库结果，并补充 PostgreSQL 14/MySQL 8.0 兼容矩阵。

## 功能：Gateway 三模式 Web 防护

- 验收：bypass 不加载 WAF；observe 记录攻击并转发；block 在上游前拦截 SQLi、XSS、路径穿越；伪造转发头不得受信。
- 命令/手工检查：`go test ./internal/gateway -v`。
- 预期：攻击在 block 返回 403 且上游命中数不增加；observe 返回上游状态并产生命中日志。
- 实际：全部通过；同时修复 Windows 下 Coraza Include 反斜杠与嵌入式 CRS 不兼容问题。
- 状态：passed
- 后续：误报基线、受信代理 CIDR、限流、GeoIP 与告警回传。

## 功能：通用一键部署探测与计划

- 验收：在支持矩阵中识别 OS、架构、systemd、Nginx、Docker/Compose 和上游候选；无歧义时生成 Gateway 计划，有歧义时仅生成 Sensor 计划并列出原因；探测阶段不修改系统。
- 命令/手工检查：夹具化 Ubuntu/Debian/Nginx/Docker 测试；`mysafe-installer inspect --json`；检查文件哈希在探测前后不变。
- 预期：相同环境产生稳定计划，不支持环境明确失败，不会猜测端口或改写配置。
- 实际：`internal/installer` 夹具测试覆盖 Ubuntu 22.04/24.04、Debian 12/13、amd64/arm64、无 systemd、不支持 OS、唯一 Nginx 上游、多个上游歧义和非法上游；自动选择空闲 Gateway 端口，探测不写目标文件系统。
- 状态：passed（夹具与本机自动化）
- 后续：在四个目标发行版的真实 amd64/arm64 systemd 主机或 VM 上复跑矩阵。

## 功能：签名发布与事务安装/回滚

- 验收：篡改任一二进制、清单或签名时拒绝安装；安装中任一步失败时恢复旧二进制、环境和 Nginx 配置；重复执行保持幂等。
- 命令/手工检查：临时根目录集成测试、Ed25519 正反例、故障注入、第二次安装与 rollback。
- 预期：成功安装产生完整事务日志；失败无半安装状态；私钥不进入仓库和构建日志。
- 实际：Ed25519 清单签名、严格 JSON schema、按架构选择、SHA-256/大小/模式校验、嵌入公钥、事务日志、旧文件备份、服务状态恢复、显式 rollback、短时令牌不落盘均已实现。故障注入验证安装失败恢复旧 Agent 和 Nginx；篡改产物/清单/签名、请求版本不一致均在事务前拒绝。Bootstrap 通过 OpenSSL 3 `pkeyutl -rawin` 自验；发布工作流包含本地 HTTP 镜像的完整 dry-run。
- 状态：passed（本机自动化）；tag 发布任务和真实 Linux 安装待首次运行
- 后续：补 `.deb`、升级灰度、真实 Ubuntu/Debian systemd 安装与回滚矩阵。

## 功能：Nginx Gateway 自动接入

- 验收：只改写探测阶段确认的唯一字面量回环 `proxy_pass`；Gateway 必须先启动并通过健康检查；`nginx -t` 成功后才 reload；任一步失败恢复原配置并重新验证/reload。
- 命令/手工检查：`go test ./internal/installer -run 'Apply|Nginx'`，注入 `nginx -t` 和服务启动失败。
- 预期：明确拓扑接入 Gateway；歧义拓扑保持 Sensor；失败不留下半切换流量。
- 实际：成功夹具先启动 Gateway 后将 `127.0.0.1:3000` 切换到本地 Gateway；歧义夹具降级 Sensor；`nginx -t` 故障夹具恢复原配置。
- 状态：passed（夹具）
- 后续：真实 Nginx 主机、include 多文件、IPv6 回环和发行版差异矩阵。

## 功能：一键 Bootstrap 下载链路

- 验收：仅下载当前架构产物；先验签再信任哈希；版本固定；失败清理临时文件且不调用 Installer；成功把同一签名 bundle 传给 Installer。
- 命令/手工检查：`go test ./internal/spec ./internal/releasebundle ./internal/installer`、Git Bash `bash -n`、OpenSSL 3 对本地签名清单验证、`actionlint`；tag 工作流本地 HTTP release server + `bootstrap.sh --dry-run`。
- 预期：错误签名、哈希或版本全部在写系统前失败；成功路径输出计划。
- 实际：本机语法、固定公钥一致性、OpenSSL Ed25519、错误版本事务前拒绝均通过；完整 Linux 下载 dry-run 已加入 tag 发布门。
- 状态：passed（静态/单元/本机 OpenSSL）；GitHub hosted Linux 路径待首次 tag 观察
- 后续：发布首个候选 tag 后记录 hosted runner 和 Artifact Attestation 结果。

## 功能：文件完整性基线与变更上报

- 验收：首次扫描只建立最小化基线；后续创建、修改、删除和权限变化产生去内容化事件；基线持久化并原子更新；符号链接、超大范围、不可读文件和批量变化有明确安全边界；控制面离线时事件进入加密队列。
- 命令/手工检查：临时目录基线/变更单元测试；Agent → 加密队列 → Control Plane 真实 HTTP 集成测试；损坏基线和扫描上限负例。
- 预期：证据只包含路径、哈希、大小、权限和变化类型，不上传文件正文；首次基线不制造篡改告警；重启后仍能比较旧基线。
- 实际：首次扫描无篡改告警并原子保存 schema 化基线；创建、正文/权限修改、删除、损坏基线、文件数上限、提交前重试幂等均有测试。变化事件先写 AES-256-GCM 队列，再提交基线；Agent → Queue → Control Plane 的真实 HTTP 测试确认正文标记未离开 Agent。`go test -race` 与 `go vet` 通过。
- 状态：passed（轮询基线）
- 后续：加入 inotify 增量加速、策略化 watch roots 和窄权限读取 helper；轮询保留为丢事件/重启后的全量保底。

## 功能：SSH 认证与爆破检测

- 验收：首次只保存日志游标；后续增量解析成功/失败认证；同一源 IP 在滑动窗口达到阈值时产生一次爆破告警；失败后成功登录升级为可疑登录；日志轮转、截断、半行、不可读和批量上限不丢失游标安全性；不上传原始日志行。
- 命令/手工检查：Ubuntu/Debian auth.log 夹具、IPv4/IPv6、invalid user、轮转/截断、跨周期窗口、Agent 加密队列与 Control Plane 集成测试。
- 预期：事件仅包含来源 IP、受限用户名、认证方法、计数和窗口；首次安装不回放整份历史日志；低频失败不制造逐条告警。
- 实际：`auth.log`/`secure` 首次游标、增量读取、半行、轮转/截断、文件后创建、IPv4/IPv6、全局行数分批、跨周期阈值、告警抑制和失败后成功均有测试；无可读文件时自动切换 systemd journal cursor，文件恢复时优先文件并重新基线 journal。Agent → AES-GCM Queue → Control Plane 真实 HTTP 测试收到爆破告警且未携带原始日志行。systemd 单元只补充 `adm`/`systemd-journal` 读组。`go test -race` 与 `go vet` 通过。
- 状态：passed（自动化/模拟 journal）
- 后续：在 Ubuntu/Debian 真实 journald 与 logrotate 上认证 cursor vacuum、权限和高频日志行为。

## 功能：进程与监听端口变化检测

- 验收：首次建立 `/proc` 基线；后续新增监听、监听关闭、首次出现的可执行身份和同名进程可执行身份漂移产生最小化事件；公网/全接口监听风险高于回环；进程抖动不按 PID 重复告警；无法读取的 proc 范围明确报告覆盖缺口。
- 命令/手工检查：procfs 夹具覆盖 tcp/tcp6、wildcard/loopback、进程 UID/名称、PID 变化、身份漂移、进程退出和上限；Agent 加密队列到 Control Plane 集成。
- 预期：不采集命令行、环境变量或进程内存；证据只包含进程名、UID、可执行路径（可读时）、端口、地址范围和协议。
- 实际：procfs 夹具覆盖 PID 抖动、首次进程身份、同名可执行身份漂移、tcp/tcp6、127/8 回环、全接口监听、端口关闭、进程/端口/文件大小上限和部分覆盖保留；不读取 `cmdline`、`environ`、fd 内容或内存。Agent → AES-GCM Queue → Control Plane 真实 HTTP 测试收到高危 wildcard 新监听事件。`go test -race` 与 `go vet` 通过；Windows 无符号链接权限时身份漂移子测试跳过，Linux CI 会执行。
- 状态：passed（自动化 procfs 夹具）
- 后续：真实 Ubuntu/Debian `hidepid`、高进程数、容器 PID namespace 与端口暴露语义测试。

## 功能：Gateway 规则命中回传 Agent

- 验收：Coraza 命中生成不含请求正文/查询值的最小事件；Gateway 仅写本地限额 outbox，通过受限 Unix socket 交给 Agent；Agent 校验 schema 后写入 AES-GCM 队列；Agent 重启期间事件保留并恢复转发；通道故障不改变 Gateway fail-open/fail-closed 业务行为。
- 命令/手工检查：SQLi/XSS/path traversal 代理请求、socket 权限/伪造/超大消息、Agent 离线后恢复、outbox 上限与完整 Gateway→Agent→Control Plane 集成测试。
- 预期：控制面收到 rule ID、规则严重度、disruptive、Gateway mode 和事务标识；不收到请求正文、Cookie、Authorization、完整 URL 或 Coraza 匹配数据。
- 实际：Gateway 规则回调构造最小事件，测试确认查询秘密、Authorization、Cookie 和匹配数据均未进入事件；Agent 离线时限额 outbox 保留原事件，恢复后 flush；socket 严格 JSON、namespace、server-owned 字段、大小和非 socket 路径均校验。Agent listener 入 AES-GCM 队列并立即唤醒上传。完整 Linux `Gateway→Unix datagram→Agent→Control` 测试已加入且交叉编译成功。
- 状态：passed（组件/交叉编译）；完整 Unix 运行路径待 Linux CI
- 后续：在 Linux CI/实机观察 socket 组权限、Agent 重启窗口和高频规则命中。

## 功能：Agent / Control mTLS 身份

- 验收：Agent 本地生成不可导出的 Ed25519 私钥和签名 CSR；Control 使用独立 Agent CA 签发短期 clientAuth 证书，URI SAN 绑定 Agent ID；注册接口允许无客户端证书，心跳/事件在启用强制模式后同时要求 mTLS 身份和设备 Bearer；错误 SAN、错误 CA、缺失证书和仅有 Token 均拒绝。
- 命令/手工检查：CA/CSR/签发/过期/文件权限单元测试；真实 TLS 注册→切换 mTLS→心跳/事件集成；服务重启证书恢复；非 TLS 配置负例。
- 预期：客户端私钥永不离开 Agent；Control 的 Agent CA 私钥不进入数据库、日志、发布包或 API；证书只用于客户端认证，不能充当服务器证书。
- 实际：独立 Agent CA、Ed25519 CSR、30 天 clientAuth 证书、SPIFFE URI SAN、TLS 1.3 服务配置、Token+mTLS 双校验、私钥/证书权限和 7 天自动轮换均已实现。真实 `httptest` TLS 链路完成无证书注册、签发、切换 mTLS、仅 Token 401、重启恢复和轮换；race/vet 通过。
- 状态：passed
- 后续：实现按 Agent 吊销、CA 灰度轮换和 OIDC 管理身份。

## 功能：Agent 策略与追加式审计

- 验收：管理端使用 `expected_revision` 乐观并发更新强类型 detector 策略；策略与审计在同一存储事务提交；Agent 通过自身 Token+mTLS 获取且只接受目标匹配、schema 合法、revision 单调的策略；本地禁用开关是远端不能突破的安全上限。
- 命令/手工检查：创建/更新/旧 revision 冲突、Agent 拉取/持久化/错误目标、审计列表/脱敏；Memory/PostgreSQL/MySQL 同一契约。
- 预期：策略丢失或旧版本不覆盖本地新版本；策略写成功必有审计，审计写失败则策略不生效。
- 实际：Memory 与 SQLStore 原子接口、PostgreSQL/MySQL `002` 迁移、Control GET/PUT、Agent 严格文件和下周期应用均已实现。控制面测试通过 revision 1、旧 revision 409、Agent 读取和审计；Agent 集成测试通过策略拉取与持久化；双数据库契约已加入 CI。
- 状态：passed（本机 Memory）；真实双库结果待 CI
- 后续：OIDC actor 替代 `admin_token` 占位身份，增加组织/项目继承、策略签名和灰度发布。

## 功能：Debian 包、升级与降级保护

- 验收：Linux release 同时生成四组件、双架构二进制和 `.deb`；所有 16 个产物进入 Ed25519 签名清单；包元数据/内容可解析，Debian 12/13 amd64 可安装并创建最小用户；安装器升级记录版本且默认拒绝降级；rollback 恢复旧版本状态。
- 命令/手工检查：Bash parser、`dpkg-deb --info/--contents`、Debian 容器 `dpkg -i`、schema v2 manifest sign/verify、版本优先级表、降级事务前拒绝、升级后 rollback。
- 预期：Bootstrap 继续选择 `binary` 格式；包和二进制不存在选择歧义；旧版本必须显式 `--allow-downgrade`；拒绝发生在事务前。
- 实际：schema v2、format-aware 选择、package 脚本、发布 16 产物断言、Ubuntu/Debian CI 矩阵、安装版本状态和降级保护已实现。Windows 已重新构建并验签 8 个 binary；本机无 `dpkg-deb`/Docker，包构建与安装等待 Linux CI。
- 状态：passed（代码/Windows 二进制）；Linux package/安装待 CI
- 后续：首次 CI 后记录四环境结果；补真实 arm64 VM、apt 仓库签名和 5%→25%→100% 灰度控制。
