/*
 * Git: https://github.com/crypery
 * Author: https://crypery.com
 * License: GNU AGPL v3 (Affero GPL)
 */

/*
 * mini-cert.c - generate a self-signed X.509 certificate and an RSA 2048-bit key.
 * Equivalent of the command:
 *
 *   openssl req -x509 -nodes -newkey rsa:2048 -sha256 \
 *     -keyout private.key -out certificate.crt -days 365
 *
 * Usage: mini-cert -keyout <file> -out <file> -subj "<subject>" [-days <n>]
 *
 * Cross-platform:
 *   - POSIX (Linux/macOS): POSIX file APIs (open/write/close)
 *   - Windows: WinSock2 (WSAStartup/WSACleanup) and WinAPI (CreateFileA/WriteFile)
 *
 * The generation logic is exported as gen_cert_run() with C linkage, so the
 * file can also be compiled as C++ or called from C++ code.
 */

#ifdef __cplusplus
extern "C" {
#endif

#include "tls.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#else
#include <fcntl.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#endif

static const char b64t[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

static char *base64_encode(const uint8_t *in, int len) {
    char *out = (char*)malloc((size_t)len * 4 / 3 + 8);
    if (!out) return NULL;
    int o = 0;
    for (int i = 0; i < len; i += 3) {
        uint32_t v = ((uint32_t)in[i] << 16);
        int rem = len - i;
        if (rem > 1) v |= ((uint32_t)in[i+1] << 8);
        if (rem > 2) v |= (uint32_t)in[i+2];
        out[o++] = b64t[(v >> 18) & 0x3F];
        out[o++] = b64t[(v >> 12) & 0x3F];
        out[o++] = rem > 1 ? b64t[(v >> 6) & 0x3F] : '=';
        out[o++] = rem > 2 ? b64t[v & 0x3F] : '=';
    }
    out[o] = '\0';
    return out;
}

/* Write a whole buffer to a file using native OS APIs:
 * WinAPI (CreateFileA/WriteFile) on Windows, POSIX (open/write) elsewhere. */
static int write_file_bytes(const char *path, const void *buf, size_t len) {
#ifdef _WIN32
    HANDLE h = CreateFileA(path, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS,
                           FILE_ATTRIBUTE_NORMAL, NULL);
    if (h == INVALID_HANDLE_VALUE) return -1;
    DWORD w = 0;
    BOOL ok = WriteFile(h, buf, (DWORD)(len < 0xFFFFFFFFu ? len : 0xFFFFFFFFu), &w, NULL);
    CloseHandle(h);
    return ok ? 0 : -1;
#else
    int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0600);
    if (fd < 0) return -1;
    size_t off = 0;
    while (off < len) {
        ssize_t w = write(fd, (const char*)buf + off, len - off);
        if (w <= 0) { close(fd); return -1; }
        off += (size_t)w;
    }
    if (close(fd) != 0) return -1;
    return 0;
#endif
}

static int pem_write(const char *filename, const char *label, const uint8_t *data, int len) {
    char *encoded = base64_encode(data, len);
    if (!encoded) return -1;
    size_t elen = strlen(encoded);
    size_t lines = (elen + 63) / 64;
    size_t cap = 128 + elen + lines + 2 * strlen(label);
    char *pem = (char*)malloc(cap);
    if (!pem) { free(encoded); return -1; }
    size_t o = 0;
    o += (size_t)snprintf(pem + o, cap - o, "-----BEGIN %s-----\n", label);
    for (size_t i = 0; i < elen; i += 64) {
        size_t n = (elen - i < 64) ? (elen - i) : 64;
        memcpy(pem + o, encoded + i, n);
        o += n;
        pem[o++] = '\n';
    }
    o += (size_t)snprintf(pem + o, cap - o, "-----END %s-----\n", label);
    int rc = write_file_bytes(filename, pem, o) == 0 ? 0 : -1;
    free(pem);
    free(encoded);
    return rc;
}

/* --- minimal DER encoder (PKCS#1 RSAPrivateKey) --- */
static int der_enc_len(uint8_t *out, int len) {
    if (len < 0x80) { out[0] = (uint8_t)len; return 1; }
    if (len < 0x100) { out[0] = 0x81; out[1] = (uint8_t)len; return 2; }
    if (len < 0x10000) { out[0] = 0x82; out[1] = (uint8_t)(len >> 8); out[2] = (uint8_t)(len & 0xFF); return 3; }
    return 0;
}

static int der_header(uint8_t *out, uint8_t tag, int content_len) {
    out[0] = tag;
    int l = der_enc_len(out + 1, content_len);
    return 1 + l;
}

static int der_push(uint8_t *out, int p, uint8_t tag, const uint8_t *content, int content_len) {
    int h = der_header(out + p, tag, content_len);
    if (content_len > 0) memcpy(out + p + h, content, (size_t)content_len);
    return p + h + content_len;
}

static int der_integer(uint8_t *out, const uint8_t *val, int len) {
    int vlen = len;
    if (val[0] & 0x80) vlen++;
    int h = der_header(out, 0x02, vlen);
    int p = h;
    if (vlen > len) out[p++] = 0x00;
    memcpy(out + p, val, (size_t)len);
    return p + len;
}

static int build_private_pkcs1(const RSAKey *key, uint8_t *out) {
    uint8_t body[1200];
    int p = 0;
    uint8_t ver = 0;
    p += der_integer(body + p, &ver, 1);
    p += der_integer(body + p, key->n, key->n_len);
    p += der_integer(body + p, key->e, key->e_len);
    p += der_integer(body + p, key->d, sizeof(key->d));
    p += der_integer(body + p, key->p, sizeof(key->p));
    p += der_integer(body + p, key->q, sizeof(key->q));
    p += der_integer(body + p, key->dmp1, sizeof(key->dmp1));
    p += der_integer(body + p, key->dmq1, sizeof(key->dmq1));
    p += der_integer(body + p, key->iqmp, sizeof(key->iqmp));
    return der_push(out, 0, 0x30, body, p);
}

static void print_help(FILE *out, const char *prog) {
    fprintf(out,
        "gen_cert - generate a self-signed X.509 certificate and an RSA 2048-bit key.\n"
        "\n"
        "Usage:\n"
        "  %s -keyout <file> -out <file> -subj \"<subject>\" [-days <n>] [-h]\n"
        "\n"
        "Required arguments:\n"
        "  -keyout <file>   File to write the private RSA key into (e.g. private.key)\n"
        "  -out <file>      File to write the certificate into (e.g. certificate.crt)\n"
        "\n"
        "Optional arguments:\n"
        "  -subj <subject>  Certificate subject in OpenSSL format, for example:\n"
        "                     -subj \"/C=US/ST=New York/L=New York/O=MyCompany/CN=localhost\"\n"
        "                   Allowed fields (separated by '/'): C, ST, L, O, OU, CN.\n"
        "                   If not specified, the default is used: /CN=ftps server\n"
        "  -days <n>        Certificate validity period in days (default 365)\n"
        "  -h, -help        Show this help\n"
        "\n"
        "Example:\n"
        "  %s -keyout private.key -out certificate.crt\n"
        "     -subj \"/C=US/ST=New York/L=New York/O=MyCompany/CN=localhost\" -days 365\n",
        prog, prog);
}

/* Parse a -subj value like "/C=...": returns 0 on success, -1 on error. */
static int parse_subj(const char *subj, CertSubject *out) {
    memset(out, 0, sizeof(*out));
    const char *s = subj;
    while (*s) {
        if (*s != '/') return -1;
        s++;
        const char *eq = strchr(s, '=');
        if (!eq) return -1;
        const char *val = eq + 1;
        const char *next = strchr(val, '/');
        size_t keylen = (size_t)(eq - s);
        size_t vallen = next ? (size_t)(next - val) : strlen(val);

        char *dst = NULL; size_t dstsz = 0;
        if (keylen == 1 && memcmp(s, "C", 1) == 0)          { dst = out->country;    dstsz = sizeof(out->country); }
        else if (keylen == 2 && memcmp(s, "ST", 2) == 0)    { dst = out->state;      dstsz = sizeof(out->state); }
        else if (keylen == 1 && memcmp(s, "L", 1) == 0)     { dst = out->locality;   dstsz = sizeof(out->locality); }
        else if (keylen == 1 && memcmp(s, "O", 1) == 0)     { dst = out->org;        dstsz = sizeof(out->org); }
        else if (keylen == 2 && memcmp(s, "OU", 2) == 0)    { dst = out->org_unit;   dstsz = sizeof(out->org_unit); }
        else if (keylen == 2 && memcmp(s, "CN", 2) == 0)    { dst = out->common_name; dstsz = sizeof(out->common_name); }
        else return -1;   /* unknown field */

        if (vallen == 0) return -1;
        if (vallen >= dstsz) return -1;   /* value too long */
        memcpy(dst, val, vallen); dst[vallen] = 0;

        if (!next) break;
        s = next;
    }
    return 0;
}

static int gen_cert_impl(int argc, char **argv) {
    const char *keyout = NULL, *outfile = NULL, *subj = NULL;
    int days = 365;

    for (int i = 1; i < argc; i++) {
        const char *a = argv[i];
        if (strcmp(a, "-h") == 0 || strcmp(a, "-help") == 0 || strcmp(a, "--help") == 0) {
            print_help(stdout, argv[0]);
            return 0;
        } else if (strcmp(a, "-keyout") == 0) {
            if (i + 1 >= argc) { fprintf(stderr, "Error: no file specified for -keyout\n"); print_help(stderr, argv[0]); return 1; }
            keyout = argv[++i];
        } else if (strcmp(a, "-out") == 0) {
            if (i + 1 >= argc) { fprintf(stderr, "Error: no file specified for -out\n"); print_help(stderr, argv[0]); return 1; }
            outfile = argv[++i];
        } else if (strcmp(a, "-subj") == 0) {
            if (i + 1 >= argc) { fprintf(stderr, "Error: no subject specified for -subj\n"); print_help(stderr, argv[0]); return 1; }
            subj = argv[++i];
        } else if (strcmp(a, "-days") == 0) {
            if (i + 1 >= argc) { fprintf(stderr, "Error: no number of days specified for -days\n"); print_help(stderr, argv[0]); return 1; }
            days = atoi(argv[++i]);
            if (days <= 0) { fprintf(stderr, "Error: -days must be a positive number (got \"%s\")\n", argv[i]); print_help(stderr, argv[0]); return 1; }
        } else {
            fprintf(stderr, "Error: unknown argument \"%s\"\n", a);
            print_help(stderr, argv[0]);
            return 1;
        }
    }

    if (!keyout || !outfile) {
        fprintf(stderr, "Error: required arguments -keyout or -out not specified.\n");
        print_help(stderr, argv[0]);
        return 1;
    }

    CertSubject subject;
    int use_subject = 0;
    if (subj) {
        if (*subj == '\0') {
            fprintf(stderr, "Error: -subj must not be an empty string.\n");
            print_help(stderr, argv[0]);
            return 1;
        }
        if (parse_subj(subj, &subject) != 0) {
            fprintf(stderr, "Error: invalid -subj format \"%s\"\n", subj);
            fprintf(stderr, "Expected format: /C=..[/ST=..][/L=..][/O=..][/OU=..][/CN=..], "
                            "e.g. /C=US/ST=New York/L=New York/O=MyCompany/CN=localhost\n");
            print_help(stderr, argv[0]);
            return 1;
        }
        subject.days = days;
        use_subject = 1;
    }

    printf("Generating RSA 2048-bit key... ");
    RSAKey key;
    if (tls_rsa_generate_key(&key) != 0) {
        fprintf(stderr, "FAILED\n");
        return 1;
    }
    printf("done\n");

    printf("Generating self-signed certificate (subject %s)... ",
           use_subject ? subj : "/CN=ftps server");
    uint8_t cert[4096];
    int cert_len = 0;
    int rc = use_subject
        ? tls_generate_self_signed_cert_ex(&key, &subject, cert, &cert_len)
        : tls_generate_self_signed_cert(&key, cert, &cert_len);
    if (rc != 0) {
        fprintf(stderr, "FAILED\n");
        return 1;
    }
    printf("done (%d bytes)\n", cert_len);

    printf("Writing %s... ", keyout);
    uint8_t pkcs1[2048];
    int pkcs1_len = build_private_pkcs1(&key, pkcs1);
    if (pkcs1_len <= 0) {
        fprintf(stderr, "FAILED\n");
        return 1;
    }
    if (pem_write(keyout, "RSA PRIVATE KEY", pkcs1, pkcs1_len) != 0) {
        fprintf(stderr, "FAILED\n");
        return 1;
    }
    printf("done\n");

    printf("Writing %s... ", outfile);
    if (pem_write(outfile, "CERTIFICATE", cert, cert_len) != 0) {
        fprintf(stderr, "FAILED\n");
        return 1;
    }
    printf("done\n");

    printf("Certificate generation complete!\n");
    printf("  Private key: %s\n", keyout);
    printf("  Certificate: %s\n", outfile);
    return 0;
}

/* Public entry point with C linkage; callable from C and C++ code.
 * On Windows it initializes WinSock2 before doing the work. */
int gen_cert_run(int argc, char **argv) {
#ifdef _WIN32
    WSADATA wsa;
    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) {
        fprintf(stderr, "Error: WSAStartup failed\n");
        return 1;
    }
#endif
    int rc = gen_cert_impl(argc, argv);
#ifdef _WIN32
    WSACleanup();
#endif
    return rc;
}

#ifdef __cplusplus
}
#endif

int main(int argc, char **argv) {
    return gen_cert_run(argc, argv);
}