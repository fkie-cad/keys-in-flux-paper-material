## Supported Implementations

| Implementation | Version | Client | Server | Rekey Support |
|----------------|---------|--------|--------|---------------|
| BoringSSL | 42d9a13df20d7b005ca0e9d646a47c14cae7ad85 | ✓  | ✗  | ✓  (TLS 1.3) |
| Botan | 3.9.0 | ✓  | ✗  |   ✓  (TLS 1.3) |
| GnuTLS | 3.8.10 | ✓  | ✓  |  ✓  (TLS 1.3) |
| Go crypto/tls | go1.23.2 linux/amd6 | ✓  | ✗   |  ✓  (TLS 1.3) |
| LibreSSL | v3.9.0 | ✓  | ✗  |   ✓  (TLS 1.3) |
| LibreTLS | v3.9.0 | ✓  | ✗  |   ✓  (TLS 1.3) |
| MatrixSSL | 4.2.1 | ✓  | ✗  |  ✗ |
| Mbed TLS | v3.6.0 | ✓  | ✗  |   ✗ |
| NSS | NSS_3_117_BETA1-0-56755612c63f | ✓  | ✗  |   ✓  (TLS 1.3) |
| OpenSSL | openssl-3.4.0 | ✓  | ✗  |   ✓  (TLS 1.3) |
| Rustls | 0.23.32 | ✓  | ✗  |   ✓  (TLS 1.3) |
| S2n-tls | v1.5.27-4 | ✓  | ✗  |   ✓  (TLS 1.3) |
| wolfSSL | v5.8.2 | ✓  | ✗  |   ✓  (TLS 1.3) |
| Schannel | Windows 11 Home 10.0.26100.6899  | ✓  | ✗  |   ✓  (TLS 1.3) |

We evaluated our results on a Ubuntu 24.04 with Kernel version 6.12.33+kali-amd64 and Windows 11 Home 10.0.26100.6899.

