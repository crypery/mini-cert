# Self-signed certificate and key generator for https

> [Russian version](README_RU.md)

> [China version](README_CN.md)

The `mini-cert` utility generates a self-signed X.509 certificate and a 2048-bit RSA private key, with the ability to add a CertSubject (equivalent to the `openssl req -x509 -nodes -newkey rsa:2048 -sha256` command).

## Features

- **Certificate generation** - self-signed X.509 certificates (DER/PEM)
- **Autonomy** - no third-party libraries required
- **Small size** - optimized code, minimal binary size
- **Cross-platform** - Windows (MinGW/GCC) and Unix-like systems

## Modules used

The utility is built on top of the [crypery](crypery/README.md) network stack - a pure C implementation with no external cryptographic dependencies. The build includes four modules:

- **tls** - the base cryptographic layer: TLS 1.2/1.3, AES-128-GCM, SHA-256, HMAC/HKDF, RSA-2048, ECDH (P-256, X25519), generation and parsing of self-signed X.509 certificates (DER/PEM). This is the module `mini-cert` uses to generate the key and certificate.
- **ssl** - an OpenSSL-compatible API layer over the built-in TLS implementation: loading certificates and keys from PEM, handshakes, encrypted I/O.
- **http** - an HTTP/1.1 server: routing, static file serving, WebSocket, SSE, gzip compression (disabled via the `HTTP_NO_GZIP` flag).
- **url** - an HTTP/HTTPS client: URL parsing, request execution, redirect handling, multipart/form-data.

## Parameters

Required parameters:

| Parameter | Description |
|-----------|-------------|
| `-keyout <file>` | File to write the private RSA key to (e.g. `private.key`) |
| `-out <file>` | File to write the certificate to (e.g. `certificate.crt`) |

Optional parameters:

| Parameter | Description |
|-----------|-------------|
| `-subj "<subject>"` | Subject in OpenSSL format: `/C=RU/ST=Moscow/L=Moscow/O=MyCompany/CN=localhost`. Fields: `C`, `ST`, `L`, `O`, `OU`, `CN` (separator `/`). If not specified, the default `CN=ftps server` is used |
| `-days <n>` | Certificate validity period in days (default 365) |
| `-h`, `-help` | Show help |

If the required parameters are missing or incorrect, the utility prints an error message and a brief help to the console.

Help:

```bash
./mini-cert -help
```

## Result

- `private.key` - the RSA private key in PEM format (PKCS#1 RSAPrivateKey)
- `certificate.crt` - a self-signed X.509 certificate in PEM format

## Build

The build is performed by the `build_gen.bat` script (GCC/MinGW required):

```bat
build_gen.bat
```

The script compiles all crypery modules and `mini-cert.c` into a single executable:

```bat
gcc -O2 -o mini-cert.exe -I. -I./crypery./crypery/*.c mini-cert.c -DHTTP_NO_GZIP -lws2_32
```

## Usage

A ready-made example is the `test_cert.bat` script, which creates a 10-year (3650-day) certificate for `localhost`:

```bat
test_cert.bat
```

Equivalent command:

```bat
mini-cert.exe -days 3650 -keyout localhost.key -out localhost.crt -subj "/C=US/ST=New York/L=New York/O=MyCompany/CN=localhost"
```

Result: the files `localhost.key` (private key) and `localhost.crt` (certificate).

## License

GNU AGPL v3 (Affero GPL)
