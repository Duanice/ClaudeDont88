# ClaudeDont88

macOS 上 Claude Code 专用代理与断网保护的开发项目。

**当前 v0.3.0 是实验预发布。独立任务守护、故障清理和已登记后代终止可以测试；真实 Claude 的受保护启动仍然锁定。**
系统拦截、完整子进程覆盖与故障保护尚未验收，不能用于保证“绝不直连”。

## v0.3.0 的实际交付

- 每个代理、检查进程和任务都有独立 `guard-worker`。监督进程被强杀时由管道 EOF 触发清理；卡死超过约 3 秒时由 worker 的独立心跳检查触发清理。
- 任务先挂起并核验身份，监督进程确认后才执行；UI 停止发送心跳也会停止会话。清理回执缺失时保留未知状态并拒绝新会话。
- 使用含 PID 代次的审计身份终止已登记后代，支持精确签名与私有会话参数识别已知守护化程序；已测双重 fork 脱组和另一会话不受影响。
- 实际 Claude 错误采集已定位外层测试沙箱与 Electron 沙箱初始化的兼容失败。桌面代理适配仍未完成，没有关闭 Electron 沙箱来绕过失败。

继承 v0.2.0 的功能：

- 菜单栏与控制面板：运行状态、专用代理配置、保留的签名扫描及过滤实验页。关闭窗口后菜单栏继续运行。
- 启动检查：无法证明代理、美国上游、目标覆盖和系统拦截有效时拒绝启动；桌面 Code 另需代理路径验收。没有手动勾选“已验证”或 IPC 绕过开关。
- 独立 `guard-runtime` 监督进程：UI 断开控制管道时清理本会话。代理退出、出口检查失败、无效控制消息也触发停止。
- 受控进程先以挂起状态创建，核对签名后恢复；使用独立进程组。停止时先结束专用代理，再对自己的任务组发送 SIGKILL，不使用按名称杀进程。
- 本地不联网演练：真实启动测试进程及同组子进程，验证强退和退出清理。
- 独立 mihomo 配置与进程：一个明确上游、单条固定规则、无 DIRECT 备用策略、仅回环监听、随机认证、关闭 TUN/DNS 监听和控制 API。
- HTTP/HTTPS、SOCKS5、Shadowsocks、Trojan 节点表单；密码保存到本机钥匙串。运行时配置仅当前用户可读，正常停止后删除。
- 每 15 秒经专用代理访问 `https://ipwho.is/`，确认该次出口为美国；检查最长 5 秒，失败停止会话。不是实时直连检测，也不自动修改时区。

**普通 Apple ID 和缺少的扩展描述文件仍阻塞本项目系统扩展的实机加载。** 即使以后安装描述文件，当前版本也不会自动解锁 Claude；还需要实现并验证系统过滤健康证据、身份覆盖、上游故障验证和桌面路由适配。

## 使用预览

1. 打开 App，通过菜单栏进入控制面板。
2. “运行状态”里可点击“启动不联网演练”，再点击“强制结束受控任务”。不会启动 Claude。
3. “专用代理”里选择本机安装的 mihomo 可执行文件，填写一个节点并保存；本机默认检测位置为 Clash Verge 所带内核。项目不捆绑或自动下载第三方内核。
4. 启动专用代理后查看状态。没有节点时不自动读取订阅、猜测凭据或启动现有 Clash 配置。
5. “启动 Claude”按钮目前会列出缺少的保护条件并拒绝运行。
6. 选择菜单栏“退出并停止受控任务”退出；只关闭窗口不会停止菜单栏 App。

上游需填写数值 IP，避免解析上游地址产生额外 DNS 路径；TLS 节点按供应商信息填写服务器名。TLS 证书验证不能关闭。
若上游填写 `127.0.0.1:7897` 等现有本地代理，其自身的 DIRECT 策略仍未被锁定。
专用代理没有改变系统代理，也不会自动接管其他入口启动的 Claude。

## 已知边界

- 当前受控启动门禁始终缺少关键证明；CLI/桌面真实任务均未开放。不要把“美国出口检查通过”理解成保护已生效。
- 强退覆盖所属组和已登记后代；轮询仍可能漏掉快速 fork/exec。任意脱组、后台共享 supervisor、虚拟机、远程任务及其他入口启动的 Claude 均未实现完整覆盖。
- 已测试监督进程及 worker 的单独强杀/卡死；两者同时失效、系统重启和未知残留恢复尚未解决。心跳超时处理存在秒级延迟。
- 关闭代理通道不能替代系统级网络阻断。周期检查有检测间隔；SIGKILL 不能撤回已经发出的数据。
- 没有节点订阅导入、自动更新、完整桌面代理适配或可用的交互式 CLI 任务界面。
- 发布包为 ad-hoc 签名，无 Developer ID 签名/公证。Gatekeeper 可能阻止下载包；建议从源码构建，不要关闭系统安全保护。

细节见 [v0.3.0 运行模型](docs/V0.3.0.md) 和 [验证记录](docs/V0.3.0-RESULTS.md)。

后续接入实验：[Little Snitch 回环边界验证](docs/LITTLE-SNITCH-PREFLIGHT.md)。脚本只测试独立探针，不自动导入防火墙规则，也不解锁 Claude。

## 构建与验证

需要 macOS 15+、Xcode 16+、Python 3。无第三方 Swift 依赖。

```sh
swift test
python3 scripts/build_app.py
python3 scripts/probe_baseline.py build/ClaudeDont88.app/Contents/Helpers/guard-probe
python3 scripts/runtime_baseline.py build/ClaudeDont88.app/Contents/Helpers/guard-runtime
open build/ClaudeDont88.app
```

本机安装了 mihomo 时，可增加真实内核的回环夹具测试；只连接本地测试服务器：

```sh
python3 scripts/runtime_baseline.py build/ClaudeDont88.app/Contents/Helpers/guard-runtime \
  --engine '/Applications/Clash Verge.app/Contents/MacOS/verge-mihomo'
```

GitHub CI 不安装第三方代理内核；该项本机补充测试单独记录。

已安装 Claude 的手动实机测试见 [原实机记录](docs/V0.2.0-REAL-CLAUDE.md) 和 [v0.3.0 补充结果](docs/V0.3.0-RESULTS.md)。已实际启动/终止临时实例，并观察到 crashpad 脱离进程组；外层测试沙箱下完整桌面启动失败，仍未通过代理路径验收。该脚本不会打包进 App，也不会由 CI 自动运行。

## Claude 发现与过滤实验

“过滤实验”保留 v0.1 的扫描、目标登记和 `NEFilterDataProvider` 原型。当前安装的 Claude 2.42304.2 扫描到 16 个程序、13 个身份；一个脚本与缺失的独立 CLI 列为未覆盖。

```sh
build/ClaudeDont88.app/Contents/Helpers/guard-probe discover-claude
build/ClaudeDont88.app/Contents/Helpers/guard-probe identity /path/to/claude
```

扫描不会启动 Claude，身份清单仅在本次 UI 运行内保存。默认扫描 `/Applications/Claude.app`、`~/Applications/Claude.app` 中首个存在者；原生 CLI 检查 `~/.local/bin/claude`、`/opt/homebrew/bin/claude`、`/usr/local/bin/claude` 和 `~/.claude/local/claude`。
扫描退出码 `0` 为有清单且无报告项，`3` 为部分清单，`2` 为无程序登记；均不表示保护生效。

系统过滤实机实验仍需要正确签名和描述文件。参见 [过滤器边界](docs/SECURITY-MODEL.md) 与 [验收手册](docs/VALIDATION.md)。仅供隔离实验，不能据“系统配置已启用”判断安全。

## 版本管理

| 版本 | 状态 |
|---|---|
| v0.1.0 / build 2 | 签名发现、过滤原型与测试基础设施；保留原标签与发布包 |
| v0.2.0 | 菜单栏、专用代理、受控进程管理和启动门禁预览；真实 Claude 启动未开放 |
| v0.3.0 | 独立任务守护、心跳与单故障清理、已登记后代终止；真实 Claude 启动仍未开放 |
| 后续版本 | 系统过滤证明、完整任务覆盖、桌面路由与故障验收、签名和公证 |

通过功能分支和 PR 合并，发布为 Pre-release。代理凭据、订阅、私钥和本机完整日志不提交到公共仓库。

## 官方依据

- [Claude Code 网络配置与桌面会话的设置范围](https://code.claude.com/docs/en/network-config)
- [mihomo 通用配置](https://wiki.metacubex.one/en/config/general/)
- [Apple Network Extension 部署](https://developer.apple.com/documentation/technotes/tn3134-network-extension-provider-deployment)
- [Apple 网络过滤示例](https://developer.apple.com/documentation/networkextension/filtering-network-traffic)

许可证：[MIT](LICENSE)。
