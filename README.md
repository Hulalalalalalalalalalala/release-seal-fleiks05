# Release Seal

为本地文件交付目录生成可读的文件清单。需要 Python 3.10 或更高版本，当前命令仅依赖标准库。

```sh
python3 -m release_seal --help
python3 -m release_seal inventory examples/package
python3 -m release_seal demo
python3 -m unittest discover -s tests -v
```

`inventory DIRECTORY` 递归读取目录中的普通文件，在标准输出返回 JSON 数组；每项含相对于输入目录、使用 `/` 分隔的 `path`、字节数 `size` 和十六进制 `sha256`。结果按路径排序，包含隐藏文件，不包含空目录。命令不会修改输入文件。

`demo` 读取随项目提供的 `examples/package`，展示同样的文件清单。

输入必须是目录，目录树不支持符号链接和特殊文件；读取失败时向标准错误输出原因，返回状态码 2。生成过程中应保持输入目录不变。
