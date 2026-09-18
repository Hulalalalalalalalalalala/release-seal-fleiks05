# Release Seal

为本地文件交付目录生成可读的文件清单，并用 Ed25519 签名实现可信的离线交付，支持单签（清单版本 1/2）与多签阈值（版本 3）。需要 Python 3.10 或更高版本；`inventory` 仅依赖标准库，`sign`、`sign-multi`、`verify`、`trust`、`verify-trusted`、`verify-policy` 和 `demo` 需要 `cryptography` 包。

```sh
python3 -m release_seal --help
python3 -m release_seal inventory examples/package
python3 -m release_seal sign examples/package private.pem manifest.json
python3 -m release_seal sign-multi examples/package manifest.json key1.pem key2.pem key3.pem
python3 -m release_seal verify examples/package manifest.json public.pem
python3 -m release_seal trust import public.pem trust.json
python3 -m release_seal trust revoke trust.json KEY_ID "key compromised"
python3 -m release_seal verify-trusted examples/package manifest.json trust.json
python3 -m release_seal verify-policy examples/package manifest.json trust.json policy.json
python3 -m release_seal demo
python3 -m unittest discover -s tests -v
```

## inventory

`inventory DIRECTORY` 递归读取目录中的普通文件，在标准输出返回 JSON 数组；每项含相对于输入目录、使用 `/` 分隔的 `path`、字节数 `size` 和十六进制 `sha256`。结果按路径排序，包含隐藏文件，不包含空目录。命令不会修改输入文件。`inventory` 接口本身保持不变；另外提供内部使用的 `stat_snapshot`，记录每个路径的类型、`(设备号, inode)` 身份、大小和纳秒修改时间。

## sign

`sign DIRECTORY PRIVATE MANIFEST` 按 `inventory` 的规则盘点目录，用 PEM 编码的 Ed25519 私钥签名后把清单写入 MANIFEST。私钥只被读取，不会出现在任何输出或清单中。

清单为 UTF-8 JSON。当前写出版本 **2**，固定包含六个字段：`version`（`2`）、`algorithm`（`"Ed25519"`）、`hash`（`"SHA-256"`）、`key_id`、`files`（与 `inventory` 输出相同的记录数组）和 Base64 编码的 `signature`。`key_id` 是签名公钥 DER SubjectPublicKeyInfo 的 SHA-256 小写十六进制（64 位）。签名覆盖除 `signature` 外的全部字段，按键排序、无空白、不转义 Unicode 的 UTF-8 JSON（规范化规则与版本 1 相同，仅新增一个被签名字段）。

清单在目标所在目录先写入同步过的隐藏临时文件（写入后 `fsync`），再通过一次**不覆盖**的硬链接发布，最后同步目录。目标已存在时绝不覆盖或截断，原因写标准错误并返回 2；任何失败都不会留下临时文件或半截清单。

## sign-multi

`sign-multi DIRECTORY MANIFEST PRIVATE...` 用一把或多把 PEM Ed25519 私钥共同签署目录，写出版本 **3** 清单。清单固定包含五个字段：`version`（`3`）、`algorithm`（`"Ed25519"`）、`hash`（`"SHA-256"`）、`files` 与 `signatures`。`signatures` 是一个 JSON 对象，键为签名者的 `key_id`（DER SubjectPublicKeyInfo 的 SHA-256 小写十六进制），值为该签名者对规范化清单的 Base64 签名；对象按 `key_id` 排序，键唯一、非空。

每把私钥签署的是**除整个 `signatures` 对象外**的完整规范化清单——即只含 `version`、`algorithm`、`hash`、`files`、按键排序、无空白、不转义 Unicode 的同一份 UTF-8 JSON，因此所有签名者覆盖完全相同的字节。私钥同样只被读取，绝不写入清单或其他输出。

命令拒绝空密钥列表、重复密钥（按 `key_id` 去重，即使同一把钥匙放在不同文件中）以及非 Ed25519 类型的密钥；沿用 `sign` 的私钥路径保护（私钥与清单必须位于交付树之外）、扫描前后一致性检查和"临时文件 + `fsync` + 不覆盖硬链接"发布，目标已存在或任何失败都返回 2、不残留临时文件。

## verify

`verify DIRECTORY MANIFEST PUBLIC` 只信任命令行指定的 PEM Ed25519 公钥，只兼容清单版本 1 与版本 2（版本 3 多签清单请用 `verify-policy`）：先验证清单签名（版本 2 还核对 `key_id` 与该公钥一致），再重新盘点目录并逐项比对。

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

库或清单格式错误、I/O 错误等返回 2。版本 3 多签清单不由该命令处理（返回 2），请使用 `verify-policy`。该命令绝不输出成功。

## verify-policy：多签阈值与离线策略

`verify-policy DIRECTORY MANIFEST STORE POLICY` 只接受**版本 3** 多签清单，结合信任库 STORE 与阈值策略 POLICY 离线判断发布是否可信。策略为 UTF-8 JSON，恰好包含四个字段：

```json
{
  "kind": "release-seal-policy",
  "version": 1,
  "threshold": 2,
  "allowed_key_ids": ["<key id>", "<key id>"]
}
```

校验规则：`kind` 固定、`version` 必须为 `1`、`threshold` 为正整数、`allowed_key_ids` 为非空的合法 `key_id` 列表且不重复，并且 `threshold` 不超过列表长度；任何不符都是格式错误，返回 2。

清单 `signatures` 中的每个签名者，按 `key_id` 排序后逐个归类：

- `valid`：密钥在库中、状态 active、被策略允许，且其签名对"除去 `signatures` 的规范化清单"验签成功；
- `unknown`：签名者不在信任库中；
- `revoked`：库中该密钥已撤销（撤销判定优先于"不被允许"）；
- `disallowed`：密钥在库中且 active，但不在 `allowed_key_ids` 中；
- `invalid`：active、被允许，但签名验签失败（含清单被篡改）。

**只有库内不同的、active、被允许且验签成功的密钥才计数**（`matched`）。计数未达 `threshold` 时不盘点目录，直接返回 1、`"reason": "threshold_not_met"`，且 `modified`、`missing`、`unexpected` 均为空。达到阈值后才重新盘点目录：完全一致返回 0 与 `{"valid": true, ...}`；存在差异返回 1、`"reason": "file_mismatch"` 及按路径排序的原三类列表 `modified`、`missing`、`unexpected`。所有失败报告都含 `valid:false`、`threshold`、`matched`、排序后的 `matched_key_ids` 与按 `key_id` 排序的 `keys` 归类表。策略、信任库、清单格式错误、I/O 错误或扫描中目录变化返回 2。

## 扫描一致性与目录限制

所有命令沿用相同的目录限制：输入必须是目录，目录树不支持符号链接和特殊文件（读取文件时使用 `O_NOFOLLOW`，防止检查后被换成符号链接）。私钥、公钥、清单、信任库与策略文件不得位于交付目录内——既包括命令行参数，也包括盘点时在交付树中发现的同类文件。

树内敏感文件**按内容识别而非按文件名后缀**：内容无法解析为密钥的普通 `.pem`（如一段恰好以 `.pem` 命名的普通文本），以及不含清单/信任库/策略结构的普通 `.json` 配置，都可以正常交付；而真实的 Ed25519（或其他类型）PEM 私钥/公钥——无论什么文件名——以及结构匹配的版本 1/2/3 清单、信任库、策略 JSON，即使不以 `.pem`/`.json` 结尾，也会被拒绝。

签名或验证前后各取一次身份快照，核对路径、类型、文件身份 `(dev, ino)`、大小和纳秒修改时间；任何变化都返回 2，不产出清单，也不会把验证报告为成功。命令不会修改交付文件。读取失败时向标准错误输出原因，返回状态码 2。生成或验证过程中应保持输入目录不变。

## 发布耐久性

清单（`sign`/`sign-multi` 的不覆盖发布）与信任库（`trust` 的原子替换）都先把完整新内容写入已 `fsync` 的隐藏临时文件，再发布，最后 `fsync` 所在目录。若发布（硬链接或 `os.replace`）本身或之前的任一步失败，返回 2：不会有任何临时文件残留；替换场景下旧目标保持原样。若发布已经完成、但随后的目录 `fsync` 失败，也返回 2 并在标准错误说明"新目标已完整保留、但其耐久性不确定"：此时不回滚、保留完整的新目标，仅清理临时文件名（硬链接/替换已使 inode 挂在目标名下）。此前的任何失败都保持旧状态不变。

## demo

`demo` 在临时目录中复制随项目提供的 `examples/package`，生成一次性的 Ed25519 密钥对，依次演示签名、对未改动交付验证成功，以及篡改文件后验证被拒绝，结束时删除临时私钥，不留任何密钥材料。
