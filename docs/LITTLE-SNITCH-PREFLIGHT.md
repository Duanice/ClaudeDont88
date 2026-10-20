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

## 下一步仍需验证

本测试不覆盖真实 Claude、外网出口、DNS、系统代发流量、任意子进程、虚拟机或过滤器崩溃。回环测试通过也不能证明这些项目成立。

真实接入必须给专用代理独立的程序路径，只允许其访问固定上游的数值 IP/端口；不能用针对共享代理内核的规则影响日常代理。节点协议必须被完整支持，不能静默丢弃传输、安全或认证选项。公共仓库不接收节点密码、订阅链接、私有节点文件或完整 Little Snitch 备份。

资料：[规则格式](https://help.obdev.at/littlesnitch6/adv-lsrules-file-format)、[规则优先级](https://help.obdev.at/littlesnitch6/concepts-rules)、[命令行权限](https://help.obdev.at/littlesnitch6/cmd-overview)、[备份恢复](https://help.obdev.at/littlesnitch6/cmd-restore-model)。
