# Release Seal

为本地文件交付目录生成可读的文件清单，并用 Ed25519 签名实现可信的离线交付。需要 Python 3.10 或更高版本；`inventory` 仅依赖标准库，`sign`、`sign-multi`、`verify`、`trust`、`verify-trusted`、`verify-policy`、`verify-batch` 和 `demo` 需要 `cryptography` 包。

```sh
python3 -m release_seal --help
python3 -m release_seal inventory examples/package
python3 -m release_seal sign examples/package private.pem manifest.json
python3 -m release_seal sign-multi examples/package manifest.json a-private.pem b-private.pem
python3 -m release_seal verify examples/package manifest.json public.pem
python3 -m release_seal trust import public.pem trust.json
python3 -m release_seal trust revoke trust.json KEY_ID "key compromised"
python3 -m release_seal verify-trusted examples/package manifest.json trust.json
python3 -m release_seal verify-policy examples/package manifest.json trust.json policy.json
python3 -m release_seal verify-batch batch.json
python3 -m release_seal demo
python3 -m unittest discover -s tests -v
```

## inventory

`inventory DIRECTORY` 递归读取目录中的普通文件，在标准输出返回 JSON 数组；每项含相对于输入目录、使用 `/` 分隔的 `path`、字节数 `size` 和十六进制 `sha256`。结果按路径排序，包含隐藏文件，不包含空目录。命令不会修改输入文件。`inventory` 接口本身保持不变；另外提供内部使用的 `stat_snapshot`，记录每个路径的类型、`(设备号, inode)` 身份、大小和纳秒修改时间。

## sign

`sign DIRECTORY PRIVATE MANIFEST` 按 `inventory` 的规则盘点目录，用 PEM 编码的 Ed25519 私钥签名后把清单写入 MANIFEST。私钥只被读取，不会出现在任何输出或清单中。

清单为 UTF-8 JSON。当前写出版本 **2**，固定包含六个字段：`version`（`2`）、`algorithm`（`"Ed25519"`）、`hash`（`"SHA-256"`）、`key_id`、`files`（与 `inventory` 输出相同的记录数组）和 Base64 编码的 `signature`。`key_id` 是签名公钥 DER SubjectPublicKeyInfo 的 SHA-256 小写十六进制（64 位）。签名覆盖除 `signature` 外的全部字段，按键排序、无空白、不转义 Unicode 的 UTF-8 JSON（规范化规则与版本 1 相同，仅新增一个被签名字段）。

清单在目标所在目录先写入同步过的隐藏临时文件（写入后 `fsync`），再通过一次**不覆盖**的硬链接发布，最后同步目录。目标已存在时绝不覆盖或截断，原因写标准错误并返回 2；任何失败都不会留下临时文件或半截清单。若发布后的目录 `fsync` 失败，返回 2 并提示耐久性不确定：完整的新清单保留在原位，临时文件被清理；发布之前发生的失败则保持旧状态不变。

## sign-multi：多签清单（版本 3）

`sign-multi DIRECTORY MANIFEST PRIVATE...` 用一把或多把 PEM Ed25519 私钥共同签名目录盘点，写出**版本 3** 清单。私钥只被读取，不会出现在任何输出或清单中；清单与私钥同样不得位于交付目录内，目标已存在时绝不覆盖。

版本 3 清单固定包含五个字段：`version`（`3`）、`algorithm`、`hash`、`files` 和 `signatures`。`signatures` 是按 `key_id` 排序的对象，每个签名者的 `key_id` 映射到它的 Base64 签名；每把私钥签的都是**除 `signatures` 外的完整规范化清单**（规范化规则与版本 1/2 相同）。密钥列表不能为空，不允许重复（按 `key_id` 判断）或非 Ed25519 私钥，违反时返回 2 且不产生清单。

`verify` 与 `verify-trusted` 只接受版本 1/2 清单；版本 3 清单请用 `verify-policy` 校验。

## verify

`verify DIRECTORY MANIFEST PUBLIC` 只信任命令行指定的 PEM Ed25519 公钥，兼容清单版本 1 与版本 2：先验证清单签名（版本 2 还核对 `key_id` 与该公钥一致），再重新盘点目录并逐项比对。

- 完全一致：输出 `{"valid": true}`，返回 0。
- 公钥不符、签名无效、文件被篡改、缺失或多余：输出 `valid:false` 以及按路径排序的 `modified`、`missing`、`unexpected`，返回 1，不会声称成功。
- 参数、I/O、密钥或清单格式错误：原因写标准错误，返回 2。

## trust：离线公钥信任库

信任库 STORE 是一个版本化 JSON 文件（`kind: "release-seal-trust-store"`，`version: 1`），按 `key_id` 保存每个公钥：PEM 公钥文本、`active` / `revoked` 状态以及撤销原因（未撤销时为 `null`）。只接受 PEM 编码的 Ed25519 公钥；`key_id` 为 DER SubjectPublicKeyInfo 的 SHA-256 小写十六进制。

### trust import PUBLIC STORE

把公钥导入信任库（库不存在时创建）。重复导入同一把 active 公钥是幂等操作，输出 `changed: false` 且不重写文件。**已撤销的密钥永远不能通过重新导入恢复**：该操作失败、返回 2、信任库保持原样。每次更新都走"临时文件 + `fsync` + 一次 `os.replace`"的原子发布，失败无残留；替换前失败保持旧内容，替换后若目录 `fsync` 失败则返回 2、保留完整的新信任库并提示耐久性不确定。

### trust revoke STORE KEY_ID [REASON]

把 KEY_ID 标记为 `revoked` 并记录可选原因。密钥不在库中或 KEY_ID 不是 64 位小写十六进制时返回 2。对已撤销密钥重复撤销是幂等空操作，原始撤销记录（含原因）保持不变。

### verify-trusted DIRECTORY MANIFEST STORE

只信任 STORE 中的 active 公钥。版本 2 清单按其 `key_id` 在库中查找；版本 1 清单没有 `key_id`，则在库内寻找唯一能验签的 active 公钥（已撤销密钥的签名优先判为撤销）。任何失败都返回 1 且输出 `valid:false`、`key_id` 与排序后的 `modified`、`missing`、`unexpected`，并带稳定的 `reason`：

- `unknown_key`：清单签名者不在信任库（或没有任何 active 公钥能验证版本 1 签名）；
- `revoked`：签名公钥已撤销；
- `invalid_signature`：密钥存在且 active，但签名无效；
- `file_mismatch`：签名有效，但目录与清单不一致（此时列表非空）。

库或清单格式错误、I/O 错误等返回 2。该命令绝不输出成功。

### verify-policy DIRECTORY MANIFEST STORE POLICY

按离线阈值策略校验**版本 3** 多签清单。POLICY 是一个 JSON 对象，恰好包含三个字段：`version`（`1`）、`threshold`（正整数）和 `allowed_key_ids`（非空、无重复的 `key_id` 列表），且 `threshold` 不得超过列表长度；违反任一约束都返回 2。

只有**库内 active、在允许列表中且验签成功**的不同密钥才计入达成数；`signatures` 中每个 `key_id` 在输出里按序标注为 `valid`、`unknown`（不在库中）、`revoked`、`disallowed`（active 但不允许）或 `invalid`（验签失败）。

- 达成数低于 `threshold`：返回 1，输出 `valid:false`、`reason: "threshold_not_met"`、`threshold`、`verified`、各签名状态以及空的 `modified`/`missing`/`unexpected`；此时**不会**扫描目录。
- 达到阈值后才盘点目录：完全一致返回 0 并输出 `valid:true`；有差异返回 1，输出 `reason: "file_mismatch"` 和按路径排序的三类列表。
- 策略、库或清单格式错误、I/O 错误、扫描期间目录变化：返回 2。任何失败都输出 `valid:false`，绝不声称成功。

## verify-batch：批量验证

`verify-batch BATCH` 从 UTF-8 JSON 数组批量执行验证。数组每项恰好包含三个字段：`id`（唯一、非空字符串）、`command`（`verify`、`verify-trusted` 或 `verify-policy` 之一）和 `args`（与该命令参数数目一致的字符串数组）。项内的相对路径基于 BATCH 文件所在目录解析；BATCH 本身必须位于它涉及的每个交付树之外，其余限制与各命令相同。

结构错误、重复 `id` 或参数数目不符：原因写标准错误，返回 2，不输出汇总。否则按输入顺序执行各项，标准输出一份 JSON 报告：`version`（`1`）、`valid`、`summary` 和 `results`。`summary` 含 `total`（项数）以及按各项退出码统计的 `passed`（0）、`failed`（1）、`errors`（2）；`results` 按执行顺序每项含 `id` 与 `code`，退出码 0/1 附该命令的原始 `result`，退出码 2 附非空 `error`（此时不向标准错误输出）。`valid` 仅当所有项退出码均为 0 时为真；任一项为 2 返回 2，否则任一项为 1 返回 1，否则返回 0。

## 扫描一致性与目录限制

所有命令沿用相同的目录限制：输入必须是目录，目录树不支持符号链接和特殊文件（读取文件时使用 `O_NOFOLLOW`，防止检查后被换成符号链接）。私钥、公钥、清单、信任库和策略不得位于交付目录内——既包括命令行参数，也包括盘点时在交付树中发现的同类文件。树内识别**按内容而非文件名或扩展名**：普通的 `.pem`、`.json` 文件可以正常交付；任何文件只要内容被判定为密钥或受管 JSON 就会被拒绝。

- PEM 内容依次尝试 `load_pem_public_key` 与 `load_pem_private_key(password=None)`：任意算法的公钥或私钥加载成功即拒绝；加载器明确报告加密私钥缺少密码（`TypeError`）同样拒绝。DER、OpenSSH 与 PKCS#12 不作检查，证书和普通 PEM 文本可以交付。
- UTF-8 JSON 只有**完整通过**版本 1/2/3 清单、版本 1 信任库或三字段版本 1 策略的校验才被拒绝；字段不符、签名非法等畸形相似对象均可交付。

签名或验证前后各取一次身份快照，核对路径、类型、文件身份 `(dev, ino)`、大小和纳秒修改时间；任何变化都返回 2，不产出清单，也不会把验证报告为成功。命令不会修改交付文件。读取失败时向标准错误输出原因，返回状态码 2。生成或验证过程中应保持输入目录不变。

## demo

`demo` 在临时目录中复制随项目提供的 `examples/package`，生成一次性的 Ed25519 密钥对，依次演示签名、对未改动交付验证成功，以及篡改文件后验证被拒绝，结束时删除临时私钥，不留任何密钥材料。
