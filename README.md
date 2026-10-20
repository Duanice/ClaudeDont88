# ClaudeDont88

macOS 上 Claude Code 专用代理与断网保护的开发项目。

**v0.1.0 是网络过滤实验原型，不是可用于真实任务的安全保护工具。**
当前预览包没有网络扩展授权，不能拦截流量。它不会强制退出 Claude，也不会改变系统代理、时区或现有 VPN。

## 本版本实现

- Swift 原生实验界面：登记已签名程序、查看策略、在具备签名条件的构建中请求系统扩展授权。
- build 2：一键扫描已安装的 Claude 桌面包及标准位置的原生 CLI，验证 Anthropic 签名，登记包内原生可执行程序，按签名身份去重并展示未覆盖项。
- `NEFilterDataProvider` 原型：按代码签名要求和系统审计标识匹配程序，不按进程名称匹配。
- 默认拒绝目标程序全部网络；实验模式可仅放行一个明确的本地 TCP 端点。
- 显式过滤 IPv4/IPv6 回环流量，拒绝错误端口、其他地址、UDP 和无法识别的目标端点。
- 有界的已跟踪连接表；正常停用时请求丢弃已跟踪连接。崩溃场景没有经过验证。
- 可独立运行的 TCP/UDP 测试客户端、回环 echo 服务、策略及真实签名解析测试。
- GitHub Actions 构建、测试和预览包产物。

## 不能保证的事情

1. **没有证明“绝不直连”。** 单元测试验证策略函数，不证明系统实际执行了过滤。
2. **本地端口不代表美国出口。** 代理可以转为 DIRECT；v0.1.0 没有控制代理上游。
3. **身份缺失的流量不在覆盖范围。** 为不误伤无关应用，无法归属的连接会放行并记录 `UNATTRIBUTED`。
4. 只覆盖登记的签名身份。扫描可登记已安装包内的 Helper；不会包含运行时下载的程序、脚本解释器、任意子进程、系统代发 DNS、虚拟机或远程任务。
5. 启用前已经存在的连接、扩展崩溃/卡死/移除、系统切换网络和重启的行为尚未完成实机验收。
6. 没有任务启动门禁、独立代理通道、后台守护、SIGKILL、开机恢复或自动更新。后续版本实现。

详细范围见 [安全边界](docs/SECURITY-MODEL.md)，实测步骤见 [验收手册](docs/VALIDATION.md)。

## 本机构建

需要 macOS 15+、Xcode 16+（包含 macOS 15+ SDK）、Python 3。无第三方 Swift 依赖。

```sh
swift test
python3 scripts/build_app.py
python3 scripts/probe_baseline.py build/ClaudeDont88.app/Contents/Helpers/guard-probe
open build/ClaudeDont88.app
```

默认生成 ad-hoc 签名的预览 App。界面可用，扩展安装按钮禁用。
它没有 Developer ID 签名或 Apple 公证；从 GitHub 下载的预览包可能被 Gatekeeper 拦截。
建议从源代码构建，不要关闭 Gatekeeper、SIP 或其他系统保护。

点击 **“扫描已安装的 Claude”** 查看桌面版、CLI、程序清单和未覆盖项。扫描只读取文件，不启动 Claude；预览包中目标清单只保存在本次运行内。更新 Claude 后重新扫描并核对清单。

`guard-probe` 也可扫描并输出 JSON，或读取单个程序的指定代码签名要求：

```sh
build/ClaudeDont88.app/Contents/Helpers/guard-probe discover-claude
build/ClaudeDont88.app/Contents/Helpers/guard-probe discover-claude /path/to/Claude.app
build/ClaudeDont88.app/Contents/Helpers/guard-probe identity /path/to/Claude.app
build/ClaudeDont88.app/Contents/Helpers/guard-probe identity /path/to/claude
```

扫描退出码：`0` 表示扫描到程序且无报告项，`3` 表示有程序但存在未覆盖项，`2` 表示未登记任何程序；均不表示网络保护已生效。
默认检查 `/Applications/Claude.app`、`~/Applications/Claude.app` 中首个存在的 App。CLI 检查 `~/.local/bin/claude`、`/opt/homebrew/bin/claude`、`/usr/local/bin/claude`、`~/.claude/local/claude`。自定义路径可手动添加。

自动扫描要求 Apple 签名链和经本机签名核实的 Anthropic Team ID；桌面主包还须匹配官方 bundle ID。脚本安装、签名不符或检查失败会报告为未覆盖。动态库不作为独立进程登记。
“添加已签名程序…”只登记所选对象；选择整个 App 时只登记主签名。选择通用 `node`、`python`、shell 等解释器会匹配它们运行的其他任务，不能作为 Claude 专用隔离方案。

## 实验性系统扩展构建

只有普通 Apple ID 无法完成本项目所需的系统扩展签名流程。需要合适的 Apple Developer 资格、证书，以及这两个明确 App ID 的描述文件：

- `io.github.duanice.ClaudeDont88`
- `io.github.duanice.ClaudeDont88.filter`

两者均需要 `content-filter-provider-systemextension`，宿主还需要 `system-extension.install`。
描述文件必须覆盖当前测试设备/分发方式。构建脚本检查期限、Team ID、App ID 和能力。
以下流程尚未在已授权的设备上验证：

```sh
python3 scripts/build_app.py \
  --identity "Apple Development: YOUR NAME (CERTIFICATE ID)" \
  --team YOUR_TEAM_ID \
  --app-profile /private/path/host.provisionprofile \
  --filter-profile /private/path/filter.provisionprofile
```

将正确签名的 App 放入 `/Applications`，使用界面依次请求扩展授权和启用测试过滤。
首次只登记内置 `guard-probe`，不要登记生产任务。仅显示“配置已启用”不能作为验收结果。

## 版本计划

| 版本 | 目标 | 当前状态 |
|---|---|---|
| v0.1.0 | 网络过滤、身份识别、测试基础设施 | 实现与本地软件测试；系统拦截验收受签名条件阻塞 |
| v0.2.0 | 菜单栏、受控启动、强退、专用代理 | 未实现 |
| v1.0.0 | 完成故障验收，签名与公证分发 | 未实现 |

GitHub Releases 中的 `v0.1.0` 与 `v0.1.0-build.2` 均标记为 **Pre-release**，App 版本保持 `0.1.0`，当前构建号 `2`。原始标签和发布包保留。验收证据见 [build 2 验证记录](docs/V0.1.0-BUILD2-RESULTS.md) 和 [首版验证记录](docs/V0.1.0-RESULTS.md)。
首次初始化空仓库提交到 `main`；后续通过功能分支和 PR 合入。

代理订阅、节点密码、Claude 凭据、证书私钥和本机完整日志均不得提交到公共仓库。

## 官方依据

- [Claude Code 网络配置](https://code.claude.com/docs/en/network-config)
- [Apple：Network Extension 部署](https://developer.apple.com/documentation/technotes/tn3134-network-extension-provider-deployment)
- [Apple：网络过滤示例](https://developer.apple.com/documentation/networkextension/filtering-network-traffic)
- [Apple：NEFilterSettings](https://developer.apple.com/documentation/networkextension/nefiltersettings)
- [Apple：PF 不是产品 API](https://developer.apple.com/documentation/technotes/tn3165-packet-filter-is-not-api)

许可证：[MIT](LICENSE)。
