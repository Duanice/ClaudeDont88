# Little Snitch 接入：先验证回环边界

这是接入前的实验步骤，不是已完成的保护功能。产品仍保留 v0.3.0 的真实 Claude 启动门禁；本实验不会启动 Claude，也不修改系统代理。

## 为什么先测回环

目标路径为 Claude → 专用本地代理 → 固定上游。如果只能禁止外部直连，却允许访问任意本机代理或转发服务，仍不能证明只有这一条出口。因此先用独立探针检验“仅一个回环 TCP 端点可达”，再进行真实应用适配。

## 准备

1. 从 [官网下载](https://www.obdev.at/products/littlesnitch/download.html) Little Snitch。校验下载包的厂商签名，安装到 Applications，然后按 macOS 提示允许系统扩展及内容过滤。
2. 为保留其他应用原有联网行为，初始采用允许连接的静默模式。后续只添加实验目标的明确拒绝规则。扩展显示 activated enabled 只表示注册状态，不是拦截验收。
3. 在 Little Snitch 的 Security 设置中允许 Terminal 访问，再用官方命令导出配置备份。该命令需要管理员权限，备份可能包含私人规则、使用记录和设置，应只保存在本机权限受限的目录。
4. 将构建好的 `guard-probe` 复制到专用实验路径。不要对 `/usr/bin/curl`、共享代理内核或所有程序添加实验拒绝规则。

未授权演示模式每次运行三小时，网络监视器试用期为三十天。演示模式不能作为长期无人值守保护。

## 规则及接收端检查

以下占位路径需要替换为本机绝对路径：

```sh
# 导入前应全部可达
python3 scripts/littlesnitch_preflight.py /absolute/test/guard-probe \
  --baseline --report /absolute/private/baseline.json

# 只生成文件，不导入、不启用
python3 scripts/littlesnitch_preflight.py /absolute/test/guard-probe \
  --write-rules /absolute/private/probe-only.lsrules

# 审阅并导入两条探针规则，核查导出配置后再执行
python3 scripts/littlesnitch_preflight.py /absolute/test/guard-probe \
  --report /absolute/private/restricted.json
```

文件只有两条高优先级出站规则：拒绝指定探针的所有目标，单独允许它访问 `127.0.0.1:17988/TCP`。高优先级并不意味着能覆盖其他所有高优先级规则，导入后仍需检查规则冲突及实际效果。

测试在每个接收端前后运行未受该规则限制的正向对照，确认接收端仍工作。判断拒绝时同时要求探针连接失败及接收端未观察到连接或报文，不能把错误端口、失效服务器或探针启动错误当成成功阻断。

| 检查 | 导入前 | 两条规则生效后的目标 |
|---|---|---|
| IPv4 TCP，指定回环端口 | 可达 | 可达 |
| IPv4 TCP，另一个回环端口 | 可达 | 拒绝 |
| IPv4 UDP，随机回环端口 | 可达 | 拒绝 |
| IPv6 TCP，`::1` 随机端口 | 可达 | 拒绝 |
| IPv6 UDP，`::1` 随机端口 | 可达 | 拒绝 |

脚本失败返回 `2`。任何禁止端点仍可达，都应保留失败记录，不能据其他通过项目解锁真实任务。关闭实验规则后再运行 baseline，可作为回滚及归因对照。

## 原始 socket 对照

`guard-probe` 使用 Network.framework，该框架可能选择系统代理。外网探针取得响应不能单独证明它使用了直连。`littlesnitch_posix_probe.c` 提供独立的 BSD socket 探针，使用数值地址，不读取 HTTP/SOCKS 代理设置；系统路由、TUN 和其他网络扩展仍可能影响它。

```sh
clang -Wall -Wextra -Werror -O2 scripts/littlesnitch_posix_probe.c -o /absolute/test/guard-probe-posix
python3 scripts/littlesnitch_preflight.py /absolute/test/guard-probe-posix --baseline

# 仅建立 TCP 连接，不发送应用层数据；地址必须先由未受规则限制的对照确认可达
/absolute/test/guard-probe-posix connect tcp NUMERIC_IP PORT
```

对照顺序为：导入前可连接 → 限制规则启用后拒绝 → 撤销实验规则后恢复。限制期间仍需未受规则限制的正向对照。超时、服务器失效或试验程序未正常执行，不足以判定防火墙拦截成功。

`.lsrules` 交换文件与 `export-model` 备份的内部结构不同，不应直接拼接规则对象。`restore-model` 成功或导出能读到规则，均不能证明规则能匹配进程。出现疑问时，应以 Little Snitch 原生导入后的规则表示和实际连接测试为准，并核对宿主应用与辅助程序的匹配关系。不要通过修改全局放行规则解决仅限探针的试验问题。

CI 只运行两种探针的回环基线、接收端对照和失败判定反例，没有安装 Little Snitch，不能作为过滤验收。

## 通过界面添加远程测试规则组

本机 Little Snitch 6.5 的实际 File 菜单没有显示 “Import Rules from File…”。不要据安装包中的菜单字符串推断某个入口当前可用，也不要将 `.lsrules` 文件作为完整备份恢复。

可用入口为 **File → New Remote Rule Group…**，与[官方规则组说明](https://help.obdev.at/littlesnitch6/lsc-rulegroups)一致。仓库的 `examples/littlesnitch-probe-only.lsrules` 仅匹配 `/private/tmp/ClaudeDont88-firewall-probe/guard-probe-posix`，包含程序本身及 Codex 经由该程序的规则，共八条。允许范围只有 `127.0.0.1:17988/TCP`，另有全目标拒绝和 IPv4/IPv6 回环精确拒绝。

1. 用本仓库的 C 源码构建该探针。专用目录必须属于当前用户、权限为 `0700`，不得覆盖他人的目录、符号链接或已有程序。
2. 先运行基线，确认允许端点及待禁止端点均可达。
3. 将规则文件发布到自己控制的 HTTPS 地址。GitHub 使用包含完整提交 SHA 的 raw 链接，将实验固定在一个版本；不要使用随分支更新的链接。
4. 选择 New Remote Rule Group，填入链接并点击 Add。核对名称为 **ClaudeDont88 Probe Only**。启用 Active，并取消 Disable new allow rules，使两条仅限探针指定端口的允许规则也生效；否则允许端口的测试也会失败。
5. 如果 macOS 或 Little Snitch 要求管理员验证，在系统界面完成。远程规则组对所有用户生效，但本例规则仅匹配这一个专用探针。不要为了实验关闭全局过滤或其他应用的规则。
6. 导出读回，核对八条规则的程序、目标、端口、启用状态和组状态，再执行限制测试。完成后禁用或移除整个测试组，运行恢复基线并核查其他规则保持一致。

这组规则还没有通过本机拦截验收，不得直接换成 Claude 路径投入使用。

## 下一步仍需验证

本测试不覆盖真实 Claude、外网出口、DNS、系统代发流量、任意子进程、虚拟机或过滤器崩溃。回环测试通过也不能证明这些项目成立。

真实接入必须给专用代理独立的程序路径，只允许其访问固定上游的数值 IP/端口；不能用针对共享代理内核的规则影响日常代理。节点协议必须被完整支持，不能静默丢弃传输、安全或认证选项。公共仓库不接收节点密码、订阅链接、私有节点文件或完整 Little Snitch 备份。

资料：[规则格式](https://help.obdev.at/littlesnitch6/adv-lsrules-file-format)、[规则优先级](https://help.obdev.at/littlesnitch6/concepts-rules)、[命令行权限](https://help.obdev.at/littlesnitch6/cmd-overview)、[备份恢复](https://help.obdev.at/littlesnitch6/cmd-restore-model)。
