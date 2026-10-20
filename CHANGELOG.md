# 更新记录

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
