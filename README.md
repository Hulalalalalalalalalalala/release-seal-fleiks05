# Release Seal

为本地文件交付目录生成可读的文件清单，并用 Ed25519 签名实现可信的离线交付。需要 Python 3.10 或更高版本；`inventory` 仅依赖标准库，`sign`、`verify` 和 `demo` 需要 `cryptography` 包（`pip install cryptography`）。

```sh
python3 -m release_seal --help
python3 -m release_seal inventory examples/package
python3 -m release_seal sign examples/package private.pem manifest.json
python3 -m release_seal verify examples/package manifest.json public.pem
python3 -m release_seal demo
python3 -m unittest discover -s tests -v
```

`inventory DIRECTORY` 递归读取目录中的普通文件，在标准输出返回 JSON 数组；每项含相对于输入目录、使用 `/` 分隔的 `path`、字节数 `size` 和十六进制 `sha256`。结果按路径排序，包含隐藏文件，不包含空目录。命令不会修改输入文件。

`sign DIRECTORY PRIVATE MANIFEST` 用 PEM 编码的 Ed25519 私钥为目录清单签名，生成 UTF-8 JSON 清单文件。清单固定包含 `version: 1`、`algorithm: "Ed25519"`、`hash: "SHA-256"`、`files`（与 `inventory` 输出相同）和 Base64 编码的 `signature`；签名覆盖前四个字段按键排序、无空白、不转义 Unicode 的 UTF-8 JSON。私钥只读取、绝不写出或打印；清单通过临时文件原子创建，目标已存在时拒绝覆盖。

`verify DIRECTORY MANIFEST PUBLIC` 只信任指定的 PEM Ed25519 公钥，先验证清单签名再盘点目录。完全一致时输出 `{"valid": true}` 并返回 0；公钥不符、签名无效、文件被篡改、缺失或多余时返回 1，输出 `valid: false` 以及按路径排序的 `modified`、`missing`、`unexpected` 列表。

`demo` 读取随项目提供的 `examples/package` 展示清单，然后在临时目录生成一次性密钥，演示签名、验证成功和篡改被拒绝的完整流程；演示结束时删除临时私钥，不留下任何秘密。

输入必须是目录，目录树不支持符号链接和特殊文件；私钥、公钥和清单不得位于交付目录树内；扫描过程中文件发生变化会被拒绝；命令不会修改交付文件。参数、读写、密钥或清单格式错误时向标准错误输出原因并返回状态码 2。生成过程中应保持输入目录不变。
