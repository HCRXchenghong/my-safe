# 技术与架构决策

## 决策：使用 Go 1.26 单仓库实现核心服务

- 日期：2026-07-16
- 背景：项目要求轻量 Agent、Headless 控制面、可选 Gateway，并部署到 Ubuntu 22.04/24.04。
- 对比方案：Go 单仓库；Rust 多二进制；Go Agent + 其他语言控制面。
- 选择：Go 1.26；核心 HTTP 与日志优先使用标准库，按 `cmd/` 与 `internal/` 划分二进制和领域层。
- 原因：Go 官方当前稳定版为 1.26.5；单二进制、交叉编译、并发与标准库能力最贴近低资源和原生部署目标。统一语言也减少协议模型漂移。
- 数据库适配：通过 Repository 接口隔离数据库；领域层不依赖具体驱动或 SQL 方言。
- 交付适配：可直接构建 Linux amd64/arm64 二进制并由 systemd 托管。
- 来源：<https://go.dev/VERSION?m=text>、<https://go.dev/doc/devel/release>（访问日期 2026-07-16）

## 决策：PostgreSQL 与 MySQL 使用显式方言适配

- 日期：2026-07-16
- 背景：规格要求两种数据库通过同一业务测试，同时需要迁移、事务、连接池和模式安全。
- 对比方案：重型 ORM；查询生成器；`database/sql` + 显式 Repository/方言迁移。
- 选择：领域 Repository + `database/sql` 兼容适配器 + 各自迁移；开发模式提供进程内存储以便零依赖运行，生产拒绝隐式回退。
- 原因：显式 SQL 更容易审查安全系统的写入、事务和索引行为，且可避免 ORM 在两种方言间产生不可见差异。
- 数据库适配：目标基线为 PostgreSQL 14～18、MySQL 8.0/8.4；CI 最终对 PostgreSQL 与 MySQL 运行同一契约测试。PostgreSQL 当前主版本为 18，MySQL 8.4 为 LTS 线。
- 交付适配：内存模式用于本地演示；生产启动必须明确指定并成功连接数据库。
- 来源：<https://www.postgresql.org/versions.json>、<https://www.postgresql.org/support/versioning/>、<https://dev.mysql.com/doc/refman/8.4/en/mysql-releases.html>（访问日期 2026-07-16）

## 决策：原生 Linux 服务优先，容器只做集成测试

- 日期：2026-07-16
- 背景：Agent 要观察主机文件、SSH、进程和端口，容器隔离会削弱默认可见性。
- 对比方案：全容器部署；原生 systemd；两者并行作为生产首选。
- 选择：Agent 与 Gateway 原生 systemd；控制面可原生或容器化；数据库容器仅作为开发/CI 便利设施。
- 原因：原生 Agent 最接近实际宿主机权限与可观测范围，并可通过 systemd 的沙箱选项限制权限。
- 数据库适配：集成测试可用临时 PostgreSQL/MySQL 容器，生产使用外部托管或本机数据库。
- 交付适配：Ubuntu 安装脚本固定版本、校验摘要并安装 systemd 单元。
- 来源：<https://www.freedesktop.org/software/systemd/man/latest/systemd.service.html>、<https://docs.docker.com/engine/install/ubuntu/>（访问日期 2026-07-16）

## 决策：先完成核心闭环，再进入 Gateway 与 App

- 日期：2026-07-16
- 背景：远端只有范围很大的产品规格，完整生产 Beta 预计 8～12 周。
- 对比方案：同时铺开所有模块；先做 UI；先做可运行核心原型。
- 选择：依次完成领域模型/控制面、Agent 注册与队列、扫描与上报、数据库与部署，再进入 Gateway/WAF 和 App。
- 原因：每个里程碑都能通过真实链路验收，并避免 UI 或规则数量掩盖不可运行的核心。
- 数据库适配：第一里程碑先固化 Repository 契约，后续两种数据库共享契约测试。
- 交付适配：第一里程碑产出可直接运行的两个 Go 二进制和端到端冒烟测试。
- 来源：仓库 `README.md` 第 21～23 节（访问日期 2026-07-16）

## 决策：Gateway 使用 Coraza 与嵌入式 OWASP CRS

- 日期：2026-07-16
- 背景：项目需要可验证的 SQLi、XSS、路径穿越等 Web 防护，不能用少量自写正则冒充 WAF。
- 对比方案：自研规则；外置 ModSecurity；Go 内嵌 Coraza + OWASP CRS。
- 选择：Coraza v3.7.0 与 `coraza-coreruleset` v4.25.0，规则随二进制嵌入；提供 bypass/observe/block 和 fail-open/fail-closed。
- 原因：官方文档将嵌入式 CRS 包列为推荐方式；与 Go 反向代理同进程，部署接近最终单二进制形态，并保留标准 CRS 的可测试规则语义。
- 数据库适配：Gateway 当前只输出最小化结构日志；后续通过本地 Agent 通道上报告警，避免网关直接持有控制面高权限凭据。
- 交付适配：已验证 Windows 开发环境和 Linux 交叉构建；显式处理了 Windows 路径分隔符与嵌入式 FS 的兼容问题。
- 许可证：Coraza 与 CRS 为 Apache-2.0；pgx 为 MIT；go-sql-driver/mysql 为 MPL-2.0。发布制品需保留对应声明。
- 来源：<https://www.coraza.io/docs/tutorials/coreruleset/>、<https://proxy.golang.org/github.com/corazawaf/coraza/v3/@latest>、<https://proxy.golang.org/github.com/corazawaf/coraza-coreruleset/v4/@latest>（访问日期 2026-07-16）

## 决策：以“分层兼容”而不是不可证实的 99% 宣称交付

- 日期：2026-07-16
- 背景：用户要求市面项目近乎通用且一键部署；不同云、Ingress、CDN、Nginx 变量、容器网络和业务鉴权无法用同一条自动改写安全覆盖。
- 对比方案：无条件改写流量；只提供手工文档；自动探测后分层接入。
- 选择：所有受支持主机保证 Sensor 安装；只有在找到唯一、字面量、可健康检查且可回滚的上游时自动启用 Gateway；其他环境输出结构化阻塞原因和建议，不改变业务流量。
- 原因：Sensor 对语言和框架无侵入；Gateway 是额外增强。把“可安装”“可观测”“可拦截”拆开验收，能避免一键脚本把生产服务改坏后仍报告成功。
- 数据库适配：控制面继续支持 PostgreSQL/MySQL；部署器不自动接管已有业务数据库，只验证 My Safe 自身连接。
- 交付适配：稳定矩阵为 Ubuntu 22.04/24.04、Debian 12/13、amd64/arm64、systemd；Ubuntu 26.04 先列实验，因为 Ubuntu LTS 元数据在调研时仍标记未正式支持。
- 来源：<https://changelogs.ubuntu.com/meta-release-lts>、<https://www.debian.org/releases/>、<https://docs.docker.com/engine/install/ubuntu/>、<https://docs.docker.com/engine/install/debian/>（访问日期 2026-07-16）

## 决策：原子安装、签名清单和可逆 Nginx 变更

- 日期：2026-07-16
- 背景：`curl | sh`、未校验二进制和直接替换 Nginx 配置不满足安全产品的供应链与可用性要求。
- 对比方案：仅依赖 TLS 下载；容器镜像标签；Ed25519 签名版本清单 + GitHub 构建证明。
- 选择：每个版本发布 JSON 清单、SHA-256 和 Ed25519 签名；安装器先离线验证再写盘，写入事务日志。Nginx 修改必须备份、校验源哈希、执行 `nginx -t`、健康检查并支持回滚。
- 原因：Go 标准库原生提供 Ed25519；固定公钥允许离线验签，不增加目标主机运行时依赖。GitHub Artifact Attestations 作为第二层构建来源证明。
- 数据库适配：数据库迁移仍由控制面启动时执行且幂等；安装器失败不会删除或回退业务数据库。
- 交付适配：原生 systemd 最接近 Agent 的宿主机可见性；Docker/Compose 作为控制面和兼容项目的补充，而不是强制前置条件。
- 来源：<https://pkg.go.dev/crypto/ed25519>、<https://docs.github.com/en/actions/how-tos/secure-your-work/use-artifact-attestations/use-artifact-attestations>、<https://nginx.org/en/docs/control.html>、<https://www.freedesktop.org/software/systemd/man/latest/systemd.service.html>（访问日期 2026-07-16）
