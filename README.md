# Release Seal

为本地文件交付目录生成可读的文件清单，并用 Ed25519 签名实现可信的离线交付。需要 Python 3.10 或更高版本；`inventory` 仅依赖标准库，`sign`、`verify`、`trust`、`verify-trusted` 和 `demo` 需要 `cryptography` 包。

```sh
python3 -m release_seal --help
python3 -m release_seal inventory examples/package
python3 -m release_seal sign examples/package private.pem manifest.json
python3 -m release_seal verify examples/package manifest.json public.pem
python3 -m release_seal trust import public.pem trust.json
python3 -m release_seal trust revoke trust.json KEY_ID "key compromised"
python3 -m release_seal verify-trusted examples/package manifest.json trust.json
python3 -m release_seal demo
python3 -m unittest discover -s tests -v
```

## inventory

`inventory DIRECTORY` 递归读取目录中的普通文件，在标准输出返回 JSON 数组；每项含相对于输入目录、使用 `/` 分隔的 `path`、字节数 `size` 和十六进制 `sha256`。结果按路径排序，包含隐藏文件，不包含空目录。命令不会修改输入文件。`inventory` 接口本身保持不变；另外提供内部使用的 `stat_snapshot`，记录每个路径的类型、`(设备号, inode)` 身份、大小和纳秒修改时间。

## sign

`sign DIRECTORY PRIVATE MANIFEST` 按 `inventory` 的规则盘点目录，用 PEM 编码的 Ed25519 私钥签名后把清单写入 MANIFEST。私钥只被读取，不会出现在任何输出或清单中。

清单为 UTF-8 JSON。当前写出版本 **2**，固定包含六个字段：`version`（`2`）、`algorithm`（`"Ed25519"`）、`hash`（`"SHA-256"`）、`key_id`、`files`（与 `inventory` 输出相同的记录数组）和 Base64 编码的 `signature`。`key_id` 是签名公钥 DER SubjectPublicKeyInfo 的 SHA-256 小写十六进制（64 位）。签名覆盖除 `signature` 外的全部字段，按键排序、无空白、不转义 Unicode 的 UTF-8 JSON（规范化规则与版本 1 相同，仅新增一个被签名字段）。

清单在目标所在目录先写入同步过的隐藏临时文件（写入后 `fsync`），再通过一次**不覆盖**的硬链接发布，最后同步目录。目标已存在时绝不覆盖或截断，原因写标准错误并返回 2；任何失败都不会留下临时文件或半截清单。

## verify

`verify DIRECTORY MANIFEST PUBLIC` 只信任命令行指定的 PEM Ed25519 公钥，兼容清单版本 1 与版本 2：先验证清单签名（版本 2 还核对 `key_id` 与该公钥一致），再重新盘点目录并逐项比对。

- 完全一致：输出 `{"valid": true}`，返回 0。
- 公钥不符、签名无效、文件被篡改、缺失或多余：输出 `valid:false` 以及按路径排序的 `modified`、`missing`、`unexpected`，返回 1，不会声称成功。
- 参数、I/O、密钥或清单格式错误：原因写标准错误，返回 2。

## trust：离线公钥信任库

信任库 STORE 是一个版本化 JSON 文件（`kind: "release-seal-trust-store"`，`version: 1`），按 `key_id` 保存每个公钥：PEM 公钥文本、`active` / `revoked` 状态以及撤销原因（未撤销时为 `null`）。只接受 PEM 编码的 Ed25519 公钥；`key_id` 为 DER SubjectPublicKeyInfo 的 SHA-256 小写十六进制。

### trust import PUBLIC STORE

把公钥导入信任库（库不存在时创建）。重复导入同一把 active 公钥是幂等操作，输出 `changed: false` 且不重写文件。**已撤销的密钥永远不能通过重新导入恢复**：该操作失败、返回 2、信任库保持原样。每次更新都走"临时文件 + `fsync` + 一次 `os.replace`"的原子发布，失败无残留。

### trust revoke STORE KEY_ID [REASON]

把 KEY_ID 标记为 `revoked` 并记录可选原因。密钥不在库中或 KEY_ID 不是 64 位小写十六进制时返回 2。对已撤销密钥重复撤销是幂等空操作，原始撤销记录（含原因）保持不变。

### verify-trusted DIRECTORY MANIFEST STORE

只信任 STORE 中的 active 公钥。版本 2 清单按其 `key_id` 在库中查找；版本 1 清单没有 `key_id`，则在库内寻找唯一能验签的 active 公钥（已撤销密钥的签名优先判为撤销）。任何失败都返回 1 且输出 `valid:false`、`key_id` 与排序后的 `modified`、`missing`、`unexpected`，并带稳定的 `reason`：

- `unknown_key`：清单签名者不在信任库（或没有任何 active 公钥能验证版本 1 签名）；
- `revoked`：签名公钥已撤销；
- `invalid_signature`：密钥存在且 active，但签名无效；
- `file_mismatch`：签名有效，但目录与清单不一致（此时列表非空）。

库或清单格式错误、I/O 错误等返回 2。该命令绝不输出成功。

## 扫描一致性与目录限制

所有命令沿用相同的目录限制：输入必须是目录，目录树不支持符号链接和特殊文件（读取文件时使用 `O_NOFOLLOW`，防止检查后被换成符号链接）。私钥、公钥、清单和信任库不得位于交付目录内——既包括命令行参数，也包括盘点时在交付树中发现的同类文件（按 `.pem` 内容、清单与信任库的 JSON 结构识别）。

签名或验证前后各取一次身份快照，核对路径、类型、文件身份 `(dev, ino)`、大小和纳秒修改时间；任何变化都返回 2，不产出清单，也不会把验证报告为成功。命令不会修改交付文件。读取失败时向标准错误输出原因，返回状态码 2。生成或验证过程中应保持输入目录不变。

## demo

`demo` 在临时目录中复制随项目提供的 `examples/package`，生成一次性的 Ed25519 密钥对，依次演示签名、对未改动交付验证成功，以及篡改文件后验证被拒绝，结束时删除临时私钥，不留任何密钥材料。
