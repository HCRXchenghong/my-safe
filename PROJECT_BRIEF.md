# 项目简报

## 项目标识

- 中文名：我的安全——轻量化 24 小时服务器安全防护方案
- 英文名：My Safe（代号 XGuard）
- 项目类型：软件开发（服务器 Agent、Headless 控制面、安全网关与移动 App）
- 最终交付效果：在 Ubuntu/Debian amd64/arm64 主机上执行一条经过签名校验的命令，自动探测 Nginx、Docker、systemd 和监听服务；先安装可工作的 Sensor，在拓扑无歧义且能验证回滚时自动接入 Gateway，通过无网页控制面管理资产、告警、策略和审计，并由 iOS/Android App 完成可视化与高风险操作审批。

## 目标环境

- 运行平台：Ubuntu 22.04/24.04、Debian 12/13 为稳定目标；Ubuntu 26.04 为实验目标；开发与 CI 支持 Windows、Linux
- 数据库/存储：PostgreSQL 与 MySQL；Agent 本地加密持久队列
- 部署目标：签名发布清单、Linux 静态二进制、systemd 服务、`.deb`/压缩包、一键安装与事务回滚；容器用于控制面、开发和集成测试
- 硬件：第一阶段面向 amd64/arm64 通用服务器，无专用硬件依赖

## 技术栈

- 选定技术：Go 1.26、标准库 `net/http`/`log/slog`、Coraza 3.7、OWASP CRS 4.25、Repository 边界、PostgreSQL/MySQL 方言迁移、原生 systemd 交付
- 选择原因：符合原始规格；单二进制、低常驻开销、跨架构构建和标准库安全能力适合轻量 Agent 与控制服务
- 调研日期：2026-07-16
- 资料链接：<https://go.dev/VERSION?m=text>、<https://go.dev/doc/devel/release>、<https://www.postgresql.org/versions.json>、<https://www.postgresql.org/support/versioning/>、<https://dev.mysql.com/doc/refman/8.4/en/mysql-releases.html>、<https://www.coraza.io/docs/tutorials/coreruleset/>

## UI 方向

- 视觉目标：移动优先的安全态势与审批界面；信息密度高但不制造无依据的恐慌感
- 色彩：待核心链路完成后，通过位图预览逐屏确认
- 已批准预览：无；UI 尚未进入实现阶段

## 验收标准

- 第一里程碑（可运行核心原型）：控制服务与 Agent 均可构建；Agent 能注册、心跳、执行基础扫描、在离线时加密缓存事件并恢复续传；控制面可查询脱敏告警；所有核心行为有自动化测试和真实 HTTP 链路验证。
- 最终交付：达到 `README.md` 的 MVP 验收标准，并通过支持矩阵中的原生服务、Nginx 反向代理、Docker/Compose 项目的一键部署与回滚验收；无法安全自动改流量链路时必须保持 Sensor 可用并给出机器可读原因，禁止伪装成完整 WAF 接入。
