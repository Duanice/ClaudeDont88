# 验收手册

## 分开记录证据

| 层次 | 方法 | 能证明什么 |
|---|---|---|
| 策略 | `swift test` | 输入与策略决定一致 |
| 系统身份 | XCTest 调用真实 Security.framework 和当前进程 audit token | 代码签名读取、匹配、拒绝错误身份 |
| 网络基线 | `probe_baseline.py` | 测试客户端确实能交换 TCP/UDP IPv4/IPv6 数据并正确报告失败 |
| 系统拦截 | 正确签名、系统授权后的真实流量试验 | 只对具体试验条件下的拦截行为提供证据 |
| 完整保护 | 故障矩阵、代理上游及任务终止测试 | v0.1.0 尚不具备 |

**客户端超时不能单独证明拦截成功。** 服务未启动、网络中断和过滤器阻断都可能导致超时。
每个阻断试验都需要：启用前正向对照、无关客户端对照、过滤器日志、接收端未收到标记的证据。

## 安全测试起点

只在没有真实 Claude 任务的测试环境中运行。不要为了加载扩展关闭 SIP 或 Gatekeeper。
签名和描述文件必须满足 Apple 要求；如果不具备条件，将系统测试记为 `BLOCKED`，不要记为 `PASS`。
默认预览构建刻意不能启用网络扩展。

先运行：

```sh
swift test
python3 scripts/build_app.py
python3 scripts/probe_baseline.py build/ClaudeDont88.app/Contents/Helpers/guard-probe
```

## 签名版本的本地端点实验

1. 正确签名并把 App 安装到 `/Applications`。
2. 请求系统扩展授权，确认 `systemextensionsctl list` 中该扩展已激活。
3. 先不启用过滤；启动两个测试端点（分别在终端运行）：

```sh
python3 scripts/echo_server.py --port 17897
python3 scripts/echo_server.py --port 17898
```

4. 通过 `/Applications/ClaudeDont88.app/Contents/Helpers/guard-probe exchange tcp 127.0.0.1 17897` 验证正向基线。
5. 在 App 中只添加**内置测试程序**。选择 `proxyOnly`，地址 `127.0.0.1`，端口 `17897`。这里的 echo 服务是测试夹具，不是真实代理。
6. 启用过滤，查看日志：

```sh
log stream --style compact --predicate 'subsystem == "io.github.duanice.ClaudeDont88"'
```

7. 使用同一个 App 内的探针运行：

```sh
/Applications/ClaudeDont88.app/Contents/Helpers/guard-probe exchange tcp 127.0.0.1 17897
/Applications/ClaudeDont88.app/Contents/Helpers/guard-probe exchange tcp 127.0.0.1 17898
/Applications/ClaudeDont88.app/Contents/Helpers/guard-probe exchange udp 127.0.0.1 17897
```

期望第一项收回 echo，第二和第三项阻断，服务端不收到对应数据。使用未登记的独立程序确认服务端仍可达。
若出现 `UNATTRIBUTED`，测试没有满足身份覆盖条件，不能判为通过。

8. 停止探针，停用过滤，再选择 `blockAll` 并启用；确认原本允许的端点也无法收到数据。
9. 以 `::1` 和 IPv6 echo 服务重复实验。
10. 实验完成后停止探针与服务，停用测试过滤；在系统设置中管理扩展。不要在运行任务时移除保护。

## 实机故障矩阵

下列项目必须分别记录环境、版本、执行步骤、接收端/抓包证据与结果：

| 场景 | 必须验证 |
|---|---|
| 外网 IPv4/IPv6 直连 | 登记目标拒绝；未登记对照程序可达 |
| UDP / QUIC / DNS | 原始 UDP 与系统委托解析分别检查，不能互相替代 |
| 指定端口服务停止 | 连接失败后没有尝试其他地址或端口 |
| 本地代理转为 DIRECT | 预期暴露本版本覆盖缺口，不能记为通过 |
| 端口被其他进程接管 | 预期暴露本版本覆盖缺口 |
| 启用前存在的长连接 | 单独观测；不能由新流测试推断 |
| 已允许连接正常停用 | 使用探针 COUNT 参数持续交换，检查已跟踪流结果 |
| 扩展崩溃、SIGSTOP、重启间隙 | 新连接、已有连接、排队数据分别观察；仅在隔离测试机操作 |
| UI 退出 | 过滤扩展应独立运行；仍需数据面验证 |
| 网络切换、休眠唤醒、重启 | 每次都重新检查归属和放行路径 |
| Claude CLI / Desktop Helper | 每个实际二进制的签名与连接分别登记和测试 |
| Claude 子进程、进程重归属 | 预期暴露未实现的继承覆盖，不可宣称支持 |
| 任务强制终止 | 未实现，属于后续版本 |

外网测试应使用测试者控制的接收端；内置工具只接受数值 IP，不会默认向第三方发送流量。
完整故障测试不应在正在使用的主力电脑上自动触发。
