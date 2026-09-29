# https 自签名证书与密钥生成器

> [English version](README.md)

> [Russian version](README_RU.md)

`mini-cert` 工具用于生成自签名 X.509 证书和 2048 位 RSA 私钥，支持添加 CertSubject（等效于 `openssl req -x509 -nodes -newkey rsa:2048 -sha256` 命令）。

## 特点

- **证书生成** - 自签名 X.509 证书（DER/PEM）
- **自主性** - 无需第三方库
- **体积小** - 代码经过优化，二进制文件最小化
- **跨平台** - Windows（MinGW/GCC）和类 Unix 系统

## 使用的模块

该工具基于 [crypery](crypery/README_CN.md) 网络栈构建--纯 C 实现，无外部加密依赖。编译包含四个模块：

- **tls** - 基础加密层：TLS 1.2/1.3、AES-128-GCM、SHA-256、HMAC/HKDF、RSA-2048、ECDH（P-256、X25519）、自签名 X.509 证书的生成与解析（DER/PEM）。`mini-cert` 正是使用该模块生成密钥和证书。
- **ssl** - 基于内置 TLS 实现的 OpenSSL 兼容 API 层：从 PEM 加载证书和密钥、握手、加密 I/O。
- **http** - HTTP/1.1 服务器：路由、静态文件分发、WebSocket、SSE、gzip 压缩（通过 `HTTP_NO_GZIP` 标志禁用）。
- **url** - HTTP/HTTPS 客户端：URL 解析、请求执行、重定向处理、multipart/form-data。

## 参数

必需参数：

| 参数 | 说明 |
|------|------|
| `-keyout <文件>` | 写入 RSA 私钥的文件（例如 `private.key`） |
| `-out <文件>` | 写入证书的文件（例如 `certificate.crt`） |

可选参数：

| 参数 | 说明 |
|------|------|
| `-subj "<subject>"` | OpenSSL 格式的 Subject：`/C=RU/ST=Moscow/L=Moscow/O=MyCompany/CN=localhost`。字段：`C`、`ST`、`L`、`O`、`OU`、`CN`（分隔符 `/`）。未指定时使用默认值 `CN=ftps server` |
| `-days <n>` | 证书有效期（天，默认 365） |
| `-h`、`-help` | 显示帮助 |

如果必需参数缺失或错误，工具会在控制台输出错误信息和简要帮助。

帮助：

```bash
./mini-cert -help
```

## 结果

- `private.key` - PEM 格式的 RSA 私钥（PKCS#1 RSAPrivateKey）
- `certificate.crt` - PEM 格式的自签名 X.509 证书

## 编译

编译通过 `build_gen.bat` 脚本执行（需要 GCC/MinGW）：

```bat
build_gen.bat
```

脚本将所有 crypery 模块和 `mini-cert.c` 编译为单个可执行文件：

```bat
gcc -O2 -o mini-cert.exe -I. -I./crypery./crypery/*.c mini-cert.c -DHTTP_NO_GZIP -lws2_32
```

## 使用

现成的示例是 `test_cert.bat` 脚本，为 `localhost` 创建有效期 10 年（3650 天）的证书：

```bat
test_cert.bat
```

等效命令：

```bat
mini-cert.exe -days 3650 -keyout localhost.key -out localhost.crt -subj "/C=US/ST=New York/L=New York/O=MyCompany/CN=localhost"
```

结果：文件 `localhost.key`（私钥）和 `localhost.crt`（证书）。

## 许可证

GNU AGPL v3 (Affero GPL)
