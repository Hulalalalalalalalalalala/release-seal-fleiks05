# Release Seal

为本地文件交付目录生成可读的文件清单，并用 Ed25519 签名实现可信的离线交付。需要 Python 3.10 或更高版本；`inventory` 仅依赖标准库，`sign`、`verify` 和 `demo` 需要 `cryptography` 包。

```sh
python3 -m release_seal --help
python3 -m release_seal inventory examples/package
python3 -m release_seal sign examples/package private.pem manifest.json
python3 -m release_seal verify examples/package manifest.json public.pem
python3 -m release_seal demo
python3 -m unittest discover -s tests -v
```

## inventory

`inventory DIRECTORY` 递归读取目录中的普通文件，在标准输出返回 JSON 数组；每项含相对于输入目录、使用 `/` 分隔的 `path`、字节数 `size` 和十六进制 `sha256`。结果按路径排序，包含隐藏文件，不包含空目录。命令不会修改输入文件。

## sign

`sign DIRECTORY PRIVATE MANIFEST` 按 `inventory` 的规则盘点目录，用 PEM 编码的 Ed25519 私钥签名后把清单写入 MANIFEST。私钥只被读取，不会出现在任何输出或清单中。清单以独占方式原子创建：目标已存在时拒绝覆盖，写标准错误并返回 2。

清单为 UTF-8 JSON，固定包含五个字段：`version`（`1`）、`algorithm`（`"Ed25519"`）、`hash`（`"SHA-256"`）、`files`（与 `inventory` 输出相同的记录数组）和 Base64 编码的 `signature`。签名覆盖前四个字段按键排序、无空白、不转义 Unicode 的 UTF-8 JSON。

## verify

`verify DIRECTORY MANIFEST PUBLIC` 只信任指定的 PEM Ed25519 公钥：先验证清单签名，再重新盘点目录并逐项比对。

- 完全一致：输出 `{"valid": true}`，返回 0。
- 公钥不符、签名无效、文件被篡改、缺失或多余：输出 `valid:false` 以及按路径排序的 `modified`、`missing`、`unexpected`，返回 1，不会声称成功。
- 参数、I/O、密钥或清单格式错误：原因写标准错误，返回 2。

## 限制

所有命令沿用相同的目录限制：输入必须是目录，目录树不支持符号链接和特殊文件。私钥、公钥和清单不得位于交付目录内；扫描期间目录发生变化会拒绝继续；命令不会修改交付文件。读取失败时向标准错误输出原因，返回状态码 2。生成或验证过程中应保持输入目录不变。

## demo

`demo` 在临时目录中复制随项目提供的 `examples/package`，生成一次性的 Ed25519 密钥对，依次演示签名、对未改动交付验证成功，以及篡改文件后验证被拒绝，结束时删除临时私钥，不留任何密钥材料。
