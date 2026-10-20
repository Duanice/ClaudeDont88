# 更新记录

## v0.1.0 build 2 — Pre-release

- 扫描本机 Claude 桌面包和标准位置的原生 CLI，不启动被扫描程序。
- 核验 Apple 签名链、Anthropic Team ID 和桌面 bundle ID，逐个验证包内 Mach-O 可执行程序的所有架构。
- 按具体签名要求去重，列出程序路径、版本、缺失 CLI、脚本与验证失败项目。
- 新增 `guard-probe discover-claude [APP_PATH]` JSON 清单和非完整扫描退出码。
- 新增 Mach-O 格式边界、错误发布者拒绝及清单去重测试。
- App 版本保持 `0.1.0`，构建号增为 `2`，不替换首版标签。

仍为未加载网络扩展的预览包；本次没有实现强退、代理上游锁定或完整防泄漏保护。
详见 [build 2 验证记录](docs/V0.1.0-BUILD2-RESULTS.md)。

## v0.1.0 — 2026-10-20 — Pre-release

首个网络过滤实验原型：

- 原生 macOS 测试界面与 Network Extension 数据过滤器。
- 系统审计标识、指定代码签名要求和明确目标登记。
- 默认全阻断与单个回环 TCP 端点放行策略。
- IPv4、IPv6、UDP、配置验证及真实 Security.framework 自动测试。
- 独立 TCP/UDP echo 探针、基线验证脚本和故障验收手册。
- 可重现构建脚本与 GitHub Actions。

限制：当前发布包是没有网络扩展授权的 ad-hoc 预览构建。
真实系统拦截未验收；没有代理上游锁定、子进程继承、强退或完整故障保护。
详见 [验证记录](docs/V0.1.0-RESULTS.md)。
