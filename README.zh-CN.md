# rollout_guard

[English](README.md) · [Ko-fi](https://ko-fi.com/tinkora)

一个隐私优先、完全离线的 JSONL rollout 产物检查器。它只读取用户明确指定的输入，帮助发现畸形或超大记录、嵌入式 `data:*;base64` 负载膨胀、重复记录/内容以及结构明确的重复指令。

## 安全边界

- 只读取明确指定的文件或目录；目录检查不递归，只包含当前层的 `*.jsonl`。明确指定的符号链接和所选目录中的符号链接条目都会被拒绝，不会跟随。
- 流式读取，每行最多保留 `--max-line-bytes + 1` 字节；超大行只排空、不解析。
- 不上传、删除、改写、脱敏或导出输入。
- 只报告文件名、计数和仅存在于内存中的哈希；不输出记录内容、秘密值或完整本地路径。
- 仅识别语法明确的 `data:...;base64,...` 字符串，不猜测普通字符串是否为 base64。
- 仅当顶层 `instruction`、`system_instruction` 或 `prompt` 字符串完全相同时计为重复指令。

它是边界明确的 JSONL 检查器，不是通用 Agent 日志验证器或秘密扫描器。

## 使用

```console
cargo install --path . --locked
rollout_guard ./run.jsonl
rollout_guard ./artifacts --format json
rollout_guard ./run.jsonl --format sarif > rollout_guard.sarif
```

退出码：`0` 无发现、`1` 超过阈值、`2` 输入或 I/O 错误。开发及规则说明见[英文 README](README.md)和[中文产品规格](docs/PRODUCT_SPEC.zh-CN.md)。
