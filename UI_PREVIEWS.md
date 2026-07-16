# UI 预览

核心服务已进入可供 App 对接的阶段。Flutter 代码仍未开始，必须先通过逐屏位图审批。

进入 UI 阶段时，每个屏幕会先单独生成位图预览，由用户批准后再实现并连接真实功能。

## 预览 01：安全总览首页

- 日期：2026-07-16
- 用例：`ui-mockup`
- 目标文件：`docs/ui-previews/security-overview-v1.png`
- 状态：blocked；当前会话未提供内置 `image_gen`，未生成任何替代图，未开始 Flutter 实现
- 阻断处理：根据 imagegen 技能，不能用 SVG/HTML/CSS 代替审批位图，也不能在用户未确认时切换到需要本机 `OPENAI_API_KEY` 的 CLI fallback
- 审批状态：未审批

最终生成提示：

```text
Use case: ui-mockup
Asset type: high-fidelity Flutter mobile app home screen bitmap preview
Primary request: My Safe server security mobile app “安全总览” home screen, ready-to-implement product UI rather than concept art
Scene/backdrop: a single portrait mobile screen, edge-to-edge app canvas, no phone hardware frame
Style/medium: realistic production mobile UI, calm professional security operations, precise spacing, modern sans-serif Chinese typography, accessible touch targets
Composition/framing: top app bar with “My Safe” and compact connection status; large security posture card; 2x2 metric grid; latest alerts list; five-item bottom navigation
Color palette: deep navy and graphite surfaces, restrained emerald/teal for healthy state, amber for warning, red only for critical counts; strong accessible contrast; no excessive gradients
Text (verbatim): “My Safe”, “安全总览”, “所有系统运行正常”, “受保护服务器 12”, “今日拦截 286”, “高危告警 3”, “待审批 2”, “最新告警”, “SQL 注入已阻止”, “SSH 爆破尝试”, “关键配置已修改”, “总览”, “告警”, “资产”, “策略”, “我的”
Constraints: render all listed Chinese text verbatim; one screen only; practical information hierarchy; metrics and alerts must look connected to real data; no fake terminal, no world map, no stock photo, no glassmorphism, no cyberpunk neon, no 3D illustration, no logos or trademarks, no watermark
Avoid: fear-driven visuals, decorative clutter, tiny unreadable labels, excessive red, desktop dashboard compressed into a phone
```
