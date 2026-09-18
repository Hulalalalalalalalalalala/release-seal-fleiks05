# Release Seal

为本地文件交付目录生成可读的文件清单，并用 Ed25519 签名实现可信的离线交付。需要 Python 3.10 或更高版本；`inventory` 仅依赖标准库，`sign`、`verify`、`verify-trusted`、`trust` 和 `demo` 需要 `cryptography` 包。

```sh
python3 -m release_seal --help
python3 -m release_seal inventory examples/package
python3 -m release_seal sign examples/package private.pem manifest.json
python3 -m release_seal verify examples/package manifest.json public.pem
python3 -m release_seal trust import public.pem trust-store.json
python3 -m release_seal trust revoke trust-store.json KEY_ID "原因"
python3 -m release_seal verify-trusted examples/package manifest.json trust-store.json
python3 -m release_seal demo
python3 -m unittest discover -s tests -v
```

## inventory

`inventory DIRECTORY` 递归读取目录中的普通文件，在标准输出返回 JSON 数组；每项含相对于输入目录、使用 `/` 分隔的 `path`、字节数 `size` 和十六进制 `sha256`。结果按路径排序，包含隐藏文件，不包含空目录。命令不会修改输入文件。

## sign

`sign DIRECTORY PRIVATE MANIFEST` 按 `inventory` 的规则盘点目录，用 PEM 编码的 Ed25519 私钥签名后把清单写入 MANIFEST。私钥只被读取，不会出现在任何输出或清单中。清单在同目录先写入并同步临时文件，再以不覆盖方式一次发布：目标已存在时保持不变，写标准错误并返回 2；失败时不留任何临时文件。

清单为 UTF-8 JSON，固定包含六个字段：`version`（`2`）、`algorithm`（`"Ed25519"`）、`hash`（`"SHA-256"`）、`files`（与 `inventory` 输出相同的记录数组）、`key_id`（签名公钥 DER SubjectPublicKeyInfo 的 SHA-256 小写十六进制）和 Base64 编码的 `signature`。签名覆盖除 `signature` 外的全部字段，按键排序、无空白、不转义 Unicode 的 UTF-8 JSON。

## verify

`verify DIRECTORY MANIFEST PUBLIC` 只信任指定的 PEM Ed25519 公钥：先验证清单签名，再重新盘点目录并逐项比对。兼容 version 1（无 `key_id`）和 version 2 清单。

- 完全一致：输出 `{"valid": true}`，返回 0。
- 公钥不符、签名无效、文件被篡改、缺失或多余：输出 `valid:false` 以及按路径排序的 `modified`、`missing`、`unexpected`，返回 1，不会声称成功。
- 参数、I/O、密钥或清单格式错误：原因写标准错误，返回 2。

## trust

`trust` 管理离线公钥信任库。信任库是版本化 JSON（`version: 1`），按 KEY_ID 保存 PEM 公钥、`active`/`revoked` 状态及撤销原因；加载时逐条校验公钥与 KEY_ID 一致。所有更新先写入并同步同目录临时文件再原子替换，任何错误返回 2。

- `trust import PUBLIC STORE` 导入 PEM 编码的 Ed25519 公钥（只接受 Ed25519），KEY_ID 为 DER SubjectPublicKeyInfo 的 SHA-256 小写十六进制。重复导入幂等；已撤销的键保持撤销，不会被恢复。
- `trust revoke STORE KEY_ID [REASON]` 撤销已导入的键并记录可选原因。重复撤销幂等；撤销未知键或格式非法的 KEY_ID 返回 2。

两个命令都在标准输出返回 `key_id`、`status` 和 `reason`。

## verify-trusted

`verify-trusted DIRECTORY MANIFEST STORE` 用信任库验证 version 2 清单：按清单中的 `key_id` 查找受信公钥，先验证签名，再重新盘点目录并逐项比对。

- 完全一致：输出 `{"valid": true, "key_id": ...}`，返回 0。
- 未知键、已撤销、签名无效、内容不符：输出 `valid:false`、`key_id`、稳定的 `reason`（`unknown_key`、`revoked`、`invalid_signature`、`mismatch`）以及按路径排序的 `modified`、`missing`、`unexpected`，返回 1，绝不声称成功；撤销时附带 `detail` 说明原因。
- 参数、I/O、信任库或清单格式错误：原因写标准错误，返回 2。

## 限制

所有命令沿用相同的目录限制：输入必须是目录，目录树不支持符号链接和特殊文件。私钥、公钥、清单和信任库不得位于交付目录内；扫描前后会核对路径、类型、文件身份、大小和修改时间，目录发生变化即拒绝继续，返回 2，不产出清单或成功验证；命令不会修改交付文件。读取失败时向标准错误输出原因，返回状态码 2。生成或验证过程中应保持输入目录不变。

## demo

`demo` 在临时目录中复制随项目提供的 `examples/package`，生成一次性的 Ed25519 密钥对，依次演示签名、对未改动交付验证成功、导入信任库并可信验证、篡改文件后验证被拒绝，以及撤销密钥后可信验证被拒绝，结束时删除临时私钥，不留任何密钥材料。
