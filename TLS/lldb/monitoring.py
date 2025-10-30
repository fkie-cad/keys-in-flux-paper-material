import importlib
import lldb
import time
import sys
from datetime import datetime
import os

# Client arguments
hostname = "Server"
port = "4433"
port_tls12 = "4432"

# Server dependant libraries
# TODO: This can be removed (all clients are server dependent now)
sdl = ["boringssl", "botanssl", "gnutls", "gotls","libressl", "libretls", "matrixssl", "mbedtls", "nss", "openssl", "rustls", "s2ntls", "wolfssl"]

# Library Mapping (only TLS 1.3 for now)
tls_library_mapping = {
     # key_update: tls13_receive_key_update
     # abort:ssl_process_alert
    "boringssl": {
        "module": "libssl",
        "patterns": {
            "x86_64": {
                "derive_secret": "f3 0f 1e fa 55 48 89 e5 48 83 ec 20 48 89 7d f8 48 89 75 f0 48 89 55 e0 48 89 4d e8 48 8b 45 f8 48 8d b8 c8 01 00 00 48 8b 55 e0 4c 8b 45 e8 48 8b 75 f0 48 8b 45 f8 48 89 d1 48 89 fa 48 89 c7",
                "key_update": "f3 0f 1e fa 55 48 89 e5 48 83 ec 40 48 89 7d c8 48 89 75 c0 64 48 8b 04 25 28 00 00 00 48 89 45 f8 31 c0 48 8b 45 c0 48 8b 50 10 48 8b 40 08 48 89 45 e0 48 89 55 e8 48 8d 55 df 48 8d 45 e0 48 89 d6 48 89 c7 e8 10 71 f7 ff 85 c0 74 21 48 8d 45 e0 48 89 c7 e8 78 cd f7 ff 48 85 c0 75 10 0f b6 45 df 84 c0 74 0f 0f b6 45 df 3c 01 74 07",
                "shutdown": "f3 0f 1e fa 55 48 89 e5 48 83 ec 10 48 89 7d f8 48 8b 45 f8 48 89 c7 e8 dc c0 ff ff 48 8b 45 f8 48 8b 40 28 48 85 c0 75 2e 41 b8 fb 03 00 00 48 8d 05 c7 6d 03 00 48 89 c1 ba e2 00 00 00 be 00 00 00 00 bf 10 00 00 00 e8 18 53 f9 ff",
                "cleanup": "f3 0f 1e fa 55 48 89 e5 48 83 ec 10 48 89 7d f8 48 8b 45 f8 48 89 c7 e8 5e 9b 00 00 90 c9 c3",
                "abort": "f3 0f 1e fa 55 48 89 e5 48 83 ec 30 48 89 7d e8 48 89 75 e0 48 89 55 d0 48 89 4d d8 48 8d 45 d0 48 89 c7 e8 68 b8 f6 ff 48 83 f8 02 0f 95 c0 84 c0 74 35 48 8b 45 e0 c6 00 32 41 b8 bd 01 00 00 48 8d 05 0c ae 00 00 48 89 c1 ba 66 00 00 00 be 00 00 00 00 bf 10 00 00 00",
                # TLS 1.2
                "derive_secret_12": "f3 0f 1e fa 55 48 89 e5 41 57 41 56 41 55 41 54 53 48 83 ec 58 48 89 7d c8 48 89 f0 48 89 d6 48 89 f2 48 89 45 b0 48 89 55 b8 48 89 c8 4c 89 c1 48 89 ca 48 89 45 a0 48 89 55 a8 48 8d 45 30 48 89 c7 e8 24 15 f8 ff 49 89 c7 48 8d 45 30 48 89 c7 e8 ff 14 f8 ff 49 89 c6 48 8d 45 20 48 89 c7 e8 06 15 f8 ff 49 89 c5"      
            },
        },
        "callback_file": "boringSSL_cb_13.py",
        "callback_functions": {
            "derive_secret": "boringSSL_cb_13.derive_secrets_callback",
            "key_update": "boringSSL_cb_13.key_update_callback",
            "shutdown": "boringSSL_cb_13.shutdown_callback",
            "cleanup": "boringSSL_cb_13.cleanup_callback",
            "abort": "boringSSL_cb_13.abort_callback",
            # TLS 1.2
            "derive_secret_12": "boringSSL_cb_13.derive_secrets_callback_12"
        }
    },
    # key_update: update_read_keys()
    # abort: process_alert() 
    "botanssl": {
        "module": "libbotan",
        "patterns": {
            "x86_64": { 
                "derive_secret": "F3 0F 1E FA 41 57 4D 89 CF 41 56 49 89 CE 41 55 4D 89 C5 41 54 49 89 D4 55 48 89 F5 53 48 89 FB 48 83 EC 08 48 8B 7E 28 48 8B 07 FF 10",
                "key_update": "f3 0f 1e fa 55 48 89 e5 41 56 41 55 41 54 53 48 83 ec 70 64 48 8b 04 25 28 00 00 00 48 89 45 d8 31 c0 0f b6 07 83 e8 04 3c 01 0f 87 5b 01 00 00 48 89 fb 48 8b 7f 28 49 89 f6 4c 8d 63 60 48 8b 07",
                "shutdown": "f3 0f 1e fa 48 83 ec 18 48 8b 7f 08 c7 44 24 0c 00 00 00 00 48 8d 74 24 0c 48 8b 07 ff 50 20 48 83 c4 18 c3",
                "abort": "f3 0f 1e fa 55 53 48 89 fb 48 83 ec 18 48 8d 7c 24 08 e8 e9 9e ab ff 0f b7 44 24 0a 66 85 c0 75 29 48 8b bb 88 00 00 00 c6 83 20 01 00 00 00 48 85 ff 74 05 e8 77 88 ab ff",
                # TLS 1.2
                "derive_secret_12": "f3 0f 1e fa 41 57 41 56 41 55 41 54 55 53 48 81 ec 98 00 00 00 64 48 8b 04 25 28 00 00 00 48 89 84 24 88 00 00 00 31 c0 80 7e 68 00 0f 84 96 14 b5 ff 0f b6 76 3d 4c 8d 6c 24 20 48 89 fb 4c 89 ef e8 ca d5 ad ff 48 8b 6c 24 28 48 83 fd 03 0f 84 ab 00 00 00 48 83 fd 05 0f 85 2e 04 00 00 4c 8b 74 24 20 41 81 3e 53 48 41 2d 0f 84 2f 02 00 00 4c 8d 64 24 50"
            }
        },
        "callback_file": "botanssl_cb_13.py",
        "callback_functions": {
             "derive_secret": "botanssl_cb_13.derive_secrets_callback",
             "key_update": "botanssl_cb_13.key_update_callback",
             "shutdown": "botanssl_cb_13.shutdown_callback",
             "abort": "botanssl_cb_13.abort_callback",
             # TLS 1.2
             "derive_secret_12": "botanssl_cb_13.derive_secrets_callback_12"
        }
    },
    # key_update: update_receiving_key()
    # abort: gnutls_record_recv() --> check for return < 0
    "gnutls": {
        "module": "libgnutls",
        "patterns": {
            "x86_64": {
                "derive_secret": "f3 0f 1e fa 48 83 ec 08 48 8b 7f 18 48 8b 44 24 10 48 85 ff 74 12 48 89 44 24 10 48 83 c4 08 e9 5c fe ff ff 0f 1f 40 00",
                "key_update": "55 be 70 11 01 00 48 89 fd 53 48 83 ec 08 66 83 47 08 01 e8 18 e9 fc ff 85 c0 78 2c be 03 00 00 00 48 89 ef e8 b7 ed fc ff 89 c3 85 c0 78 51 f6 85 c8 11 00 00 01 75 60",
                "shutdown": "f3 0f 1e fa 41 54 41 89 f4 55 53 8b 87 e0 01 00 00 48 89 fb 83 f8 01 74 1a 83 f8 02 74 38 85 c0 0f 85 c2 00 00 00", 
                "cleanup": "55 53 89 fb 48 83 ec 08 85 ff 0f 84 98 00 00 00 8b 05 b6 7d 1a 00 83 f8 01 74 15 85 c0 7e 09 83 e8 01 89 05 a4 7d 1a 00",
                "abort": "f3 0f 1e fa 48 83 ec 08 80 bf 18 07 00 00 00 48 89 d1 74 44 f6 87 c8 11 00 00 01 74 1b 48 89 f2 be 17 00 00 00 e8 46 b0 05 00 48 98 48 83 c4 08 c3",
                #TLS 1.2
                # TODO: Fix (cant find out_ptr)
                "derive_secret_12": "f3 0f 1e fa 55 4c 89 cd 53 4c 89 c3 48 83 ec 08 ff 74 24 38 ff 74 24 38 41 51 41 50 4c 8b 4c 24 48 4c 8b 44 24 40 e8 55 fd ff ff 48 83 c4 20 48 83 fb 0d 75 10 48 b8 6d 61 73 74 65 72 20 73 48 39 45 00 74 1b"
            }
        },
        "callback_file": "gnutls_cb_13.py",
        "callback_functions": {
            "derive_secret": "gnutls_cb_13.derive_secrets_callback",
            "key_update": "gnutls_cb_13.key_update_callback",
            "shutdown": "gnutls_cb_13.shutdown_callback",
            "cleanup": "gnutls_cb_13.cleanup_callback",
            "abort": "gnutls_cb_13.abort_callback",
            # TLS 1.2
            "derive_secret_12": "gnutls_cb_13.derive_secrets_callback_12"
        }
    },
    # Key Update: crypto/tls.(*Conn).handleKeyUpdate
    "gotls": {
        "module": "test_client",
        "patterns": {
            "x86_64": {
                "derive_secret": "49 3b 66 10 0f 86 ef 00 00 00 55 48 89 e5 48 83 ec 50 4c 89 8c 24 90 00 00 00 4c 89 94 24 98 00 00 00 48 89 44 24 60 48 89 7c 24 78 48 89 5c 24 68 48 89 4c 24 70 4c 89 84 24 88 00 00 00 48 89 b4 24 80 00 00 00",
                "key_update": "4c 8d 64 24 d0 4d 3b 66 10 0f 86 4e 06 00 00 55 48 89 e5 48 81 ec a8 00 00 00 66 44 0f d6 bc 24 a0 00 00 00 48 89 84 24 b8 00 00 00 c6 44 24 36 00 44 0f 11 7c 24 50 48 83 78 20 00 75 19 0f b7 50 64 48 8b 35 67 3b 22 00 4c 8b 05 68 3b 22 00 31 c9 e9 6d 01 00 00",
                "shutdown": "49 3b 66 10 0f 86 00 01 00 00 55 48 89 e5 48 83 ec 50 eb 03 48 89 d8 8b 88 60 03 00 00 0f ba e1 00 0f 82 cf 00 00 00 89 ca 83 c9 01 48 89 c3 89 d0 f0 0f b1 8b 60 03 00 00",
                # TLS 1.2
                "derive_secret_12": "49 3B 66 10 0F 86 E1 01 00 00 55 48 89 E5 48 83 EC 58 48 89 BC 24 88 00 00 00 4C 89 9C 24 B0 00 00 00 4C 89 94 24 A8 00 00 00 4C 89 8C 24 A0 00 00 00 48 89 8C 24 80 00 00 00 48 89 5C 24 78 48 89 44 24 70 48 8B 44 24 68 48 89 FB 48 89 F1 4C"
            }
        },
        "callback_file": "gotls_cb_13.py",
        "callback_functions": {
            "derive_secret": "gotls_cb_13.derive_secrets_callback",
            "key_update": "gotls_cb_13.key_update_callback",
            "shutdown": "gotls_cb_13.shutdown_callback",
            # TLS 1.2
            "derive_secret_12": "gotls_cb_13.derive_secrets_callback_12"
        }
    },
    # Abort: tls13_alert_received_cb
    "libressl": {
        "module": "libssl",
        "patterns": {
            "x86_64": {
                "derive_secret": "F3 0F 1E FA 41 57 49 89 D7 41 56 4D 89 CE 41 55 4D 89 C5 41 54 49 89 CC 55 53 48 89 FB 48 83 EC 78 48 89 34 24 48 8D 6C 24 20 BE 00 01 00 00 48 89 EF 64 48 8B 04 25 28 00 00 00 48 89 44 24 68 31 C0 C7 44 24 61 74 6C 73 31 48 C7 44 24 10 00 00 00 00 C7 44 24 64 31 33 20 00 E8 F0 6C 00 00",
                "key_update": "f3 0f 1e fa 48 83 ec 28 64 48 8b 04 25 28 00 00 00 48 89 44 24 18 48 8d 05 58 b1 00 00 48 c7 44 24 08 00 00 00 00 48 89 04 24 8b 47 0c 85 c0 74 1f 8b 47 10 85 c0 74 18 8b 47 14 85 c0 74 11 8b 47 18 85 c0 75 22",
                "shutdown": "f3 0f 1e fa 53 48 83 bf 30 01 00 00 00 48 89 fb 74 24 e8",
                "cleanup": "f3 0f 1e fa 48 85 ff 0f 84 b3 01 00 00 53 45 31 c0 48 89 fb 31 c9 48 8d bf b0 00 00 00 ba 10 00 00 00 be ff ff ff ff e8 64 cc fe ff 85 c0 7e 08 5b c3",
                "abort": "f3 0f 1e fa 55 48 89 d5 53 89 f3 48 83 ec 08 48 8b 82 98 00 00 00 48 85 c0 74 0a 40 0f b6 f6 40 0f b6 ff ff d0 84 db 74 67 80 fb 5a 0f 84 82 00 00 00 48 8b 45 28 0f b6 db b9 a7 00 00 00",
                # TLS 1.2
                "derive_secret_12": "F3 0F 1E FA 41 57 41 56 41 55 41 54 55 48 89 FD 53 48 89 D3 48 83 EC 38 48 89 34 24 4C 8B A4 24 A8 00 00 00 31 F6 48 89 4C 24 08 48 8B 94 24 B0 00 00 00 4C 89 44 24 10 4C 89 E7 4C 8B 6C 24 78 4C 89 4C 24 18 4C 8B B4 24 88 00 00 00 4C 8B BC 24 98 00 00 00 64 48 8B 04 25 28 00 00 00 48 89 44 24 28 31"
            }
        },
        "callback_file": "libressl_cb_13.py",
        "callback_functions": {
            "derive_secret": "libressl_cb_13.derive_secrets_callback",
            "key_update": "libressl_cb_13.key_update_callback",
            "shutdown": "libressl_cb_13.shutdown_callback",
            "cleanup": "libressl_cb_13.cleanup_callback",
            "abort": "libressl_cb_13.abort_callback",
            # TLS 1.2
            "derive_secret_12": "libressl_cb_13.derive_secrets_callback_12"
        }
    },
    "libretls": {
        "module": "libssl",
        "patterns": {
            "x86_64": {
                "derive_secret": "F3 0F 1E FA 41 57 49 89 D7 41 56 4D 89 CE 41 55 4D 89 C5 41 54 49 89 CC 55 53 48 89 FB 48 83 EC 78 48 89 34 24 48 8D 6C 24 20 BE 00 01 00 00 48 89 EF 64 48 8B 04 25 28 00 00 00 48 89 44 24 68 31 C0 C7 44 24 61 74 6C 73 31 48 C7 44 24 10 00 00 00 00 C7 44 24 64 31 33 20 00 E8 F0 6C 00 00",
                "key_update": "f3 0f 1e fa 48 83 ec 28 64 48 8b 04 25 28 00 00 00 48 89 44 24 18 48 8d 05",
                "shutdown": "f3 0f 1e fa 55 53 48 89 fb 48 83 c7 10 48 83 ec 08 e8 2a e5 ff ff f6 43 28 05 0f 84 45 01 00 00 31 ed f6 43 2c 08",
                "cleanup": "f3 0f 1e fa 48 85 ff 74 17 53 48 89 fb e8 5e de ff ff 48 89 df 5b e9 55 d8 ff ff",
                "abort": "f3 0f 1e fa 55 48 89 d5 53 89 f3 48 83 ec 08 48 8b 82 98 00 00 00 48 85 c0 74 0a 40 0f b6 f6 40 0f b6 ff ff d0 84 db 74 67 80 fb 5a 0f 84 82 00 00 00 48 8b 45 28 0f b6 db b9 a7 00 00 00",
                # TLS 1.2: prf2()
                "derive_secret_12": "F3 0F 1E FA 41 57 41 56 41 55 41 54 55 48 89 FD 53 48 89 D3 48 83 EC 38 48 89 34 24 4C 8B A4 24 A8 00 00 00 31 F6 48 89 4C 24 08 48 8B 94 24 B0 00 00 00 4C 89 44 24 10 4C 89 E7 4C 8B 6C 24 78 4C 89 4C 24 18 4C 8B B4 24 88 00 00 00 4C 8B BC 24 98 00 00 00 64 48 8B 04 25 28 00 00 00 48 89 44 24 28 31"
            }
        },
        "callback_file": "libretls_cb_13.py",
        "callback_functions":  {
            "derive_secret": "libretls_cb_13.derive_secrets_callback",
            "key_update": "libretls_cb_13.key_update_callback",
            "shutdown": "libretls_cb_13.shutdown_callback",
            "cleanup": "libretls_cb_13.cleanup_callback",
            "abort": "libretls_cb_13.abort_callback",
            # TLS 1.2
            "derive_secret_12": "libretls_cb_13.derive_secrets_callback_12"
        }
    },
    # Key Update is handled as 'unexpected message' -> no keyUpdate for now
    # Shutdown == abort in this case
    "matrixssl": {
        "module": "test_client",
        "patterns": {
            "x86_64":{
                "derive_secret": "f3 0f 1e fa 41 57 4d 89 c7 41 56 41 55 41 54 49 89 fc 55 53 44 89 cb 48 81 ec 08 01 00 00 48 8b 84 24 40 01 00 00 44 8b ac 24 50 01 00 00 89 74 24 18 48 8d 6c 24 40 44 8b b4 24 48 01 00 00 48 89 54 24 10 48 89 ee 48 89 44 24 28 48 8b 84 24 58 01 00 00",
                #matrixSslClose
                "cleanup": "f3 0f 1e fa 53 48 8d 1d 24 2e 0b 00 48 89 df e8 cc 1c 08 00 48 8d 15 d5 1c 0b 00 31 c0 b9 20 02 00 00 48 89 d7 f3 48 ab 48 89 df e8 d0 1c 08 00 48 89 df e8 e8 1c 08 00 e8 13 b8 04 00",
                # Use matrixSslProcessedData with retval check
                "abort": "f3 0f 1e fa 41 55 41 54 49 89 d4 55 53 48 83 ec 08 48 85 f6 0f 94 c0 48 85 d2 0f 94 c2 08 d0 0f 85 9b 01 00 00 48 89 fb 48 85 ff 0f 84 8f 01 00 00 48 c7 06 00 00 00 00 48 89 f5 41 c7 04 24 00 00 00 00 8b 8f f8 16 00 00 85 c9 0f 8e 0f 01 00 00",
                # TLS 1.2
                "derive_secret_12": "f3 0f 1e fa 41 57 45 89 ca 41 56 41 55 49 89 fd 41 54 41 89 f4 55 53 89 cb 48 81 ec 38 03 00 00 48 89 54 24 08 4c 89 44 24 48 44 89 4c 24 34 64 48 8b 04 25 28 00 00 00 48 89 84 24 28 03 00 00 31 c0 66 41 81 f9 e0 00 0f 87 02 05 00 00 0f b7 cb 8b 9c 24 70 03 00 00 44 89 14 24 45 0f b7 fc",
                # MatrixSSL has a different cleanup pattern for 1.2, allthough its the same function
                "cleanup_12": "f3 0f 1e fa 53 48 8d 1d c4 2c 0b 00 48 89 df e8 cc 1c 08 00 48 8d 15 75 1b 0b 00 31 c0 b9 20 02 00 00 48 89 d7 f3 48 ab 48 89 df e8 d0 1c 08 00 48 89 df e8 e8 1c 08 00 e8 13 b8 04 00"
            }
        },
        "callback_file": "matrixssl_cb_13.py",
        "callback_functions": {
            "derive_secret": "matrixssl_cb_13.derive_secrets_callback",
            "shutdown": "matrixssl_cb_13.shutdown_callback",
            "cleanup": "matrixssl_cb_13.cleanup_callback",
            "abort": "matrixssl_cb_13.abort_callback",
            # TLS 1.2
            "derive_secret_12": "matrixssl_cb_13.derive_secrets_callback_12",
            "cleanup_12": "matrixssl_cb_13.cleanup_callback_12"
        }
    },

    "mbedtls": {
        "module": "libmbedtls",
        "patterns": {
            "x86_64": {
              "derive_secret": "f3 0f 1e fa 55 48 89 e5 48 81 ec a0 00 00 00 89 7d 9c 48 89 75 90 48 89 55 88 48 89 4d 80 4c 89 85 78 ff ff ff 4c 89 8d 70 ff ff ff 48 8b 45 20 48 89 85 68 ff ff ff 64 48 8b 04 25 28 00 00 00 48 89 45 f8 31 c0 83 7d 18 00 0f 85 aa 01 00 00 c7 45 a8 69 ff ff ff 8b 45 9c 0f b6 c0",
              # mbedtls_ssl_close_notify()
              "shutdown": "f3 0f 1e fa 55 48 89 e5 48 83 ec 20 48 89 7d e8 c7 45 fc 92 ff ff ff 48 83 7d e8 00 74 0c 48 8b 45 e8 48 8b 00 48 85 c0 75 0a",
              # mbedtls_ssl_free()
              "cleanup": "f3 0f 1e fa 55 48 89 e5 48 83 ec 20 48 89 7d e8 48 83 7d e8 00 0f 84 2e 02 00 00 48 8b 45 e8 4c 8d 05 09 1c 03 00 b9 84 15 00 00 48 8d 15 ef 10 03 00 be 02 00 00 00 48 89 c7 b8 00 00 00 00 e8 53 74 fe ff 48 8b 45 e8 48 8b 80 50 01 00 00",
              "abort": "f3 0f 1e fa 55 48 89 e5 48 83 ec 20 48 89 7d e8 89 f1 89 d0 89 ca 88 55 e4 88 45 e0 c7 45 fc 92 ff ff ff 48 83 7d e8 00 74 0c 48 8b 45 e8 48 8b 00 48 85 c0",
              # TLS 1.2
              "derive_secret_12" : "f3 0f 1e fa 55 48 89 e5 48 81 ec 90 00 00 00 48 89 7d 88 48 89 75 80 48 89 95 78 ff ff ff 64 48 8b 04 25 28 00 00 00 48 89 45 f8 31 c0 c7 45 9c 92 ff ff ff 48 c7 45 b8 30 00 00 00 48 8d 05 9b 04 03 00 48 89 45 a8 48 8b 45 88 48 05 48 08 00 00 48 89 45 b0 48 c7 45 a0 40 00 00 00 48 8b 45 88 0f b6 00 84 c0 74 36 48 8b 85 78 ff ff ff 4c 8d 05 77 04 03 00 b9 3d 1b 00 00"
            },
        },
        "callback_file": "mbedtls_cb_13.py",
        "callback_functions": {
            "derive_secret": "mbedtls_cb_13.derive_secrets_callback",
            "shutdown": "mbedtls_cb_13.shutdown_callback",
            "cleanup": "mbedtls_cb_13.cleanup_callback",
            "abort": "mbedtls_cb_13.abort_callback",
            # TLS 1.2
            "derive_secret_12": "mbedtls_cb_13.derive_secrets_callback_12"
        }
    },

    "nss" : {
        # Set the module to "libssl3" as it contains the three patterns (derive_secret, key_update, abort)
        # Shutdown is from libnss3 and cleanup from libnspr4
        # KeyUpdate: tls13_HandleKeyUpdate
        # abort: ssl3_HandleAlert
        "module": "libssl3",
        "patterns": {
            "x86_64": {
                "derive_secret": "F3 0F 1E FA 55 48 89 E5 53 48 81 EC 08 01 00 00 48 89 BD 18 FF FF FF 48 89 B5 10 FF FF FF 48 89 95 08 FF FF FF 48 89 8D 00 FF FF FF 4C 89 85 F8 FE FF FF 4C 89 8D F0 FE FF FF 64 48 8B 04 25 28 00 00 00 48 89 45 E8 31 C0 48 83 BD 08 FF FF FF 00 0F 84 9E 00 00 00",
                "key_update": "f3 0f 1e fa 55 48 89 e5 41 54 53 48 83 ec 40 48 89 7d c8 48 89 75 c0 89 55 bc 64 48 8b 04 25 28 00 00 00 48 89 45 e8 31 c0 48 8d 05 68 9c 04 00 0f b6 00 3c 02 7e 46 48 8b 45 c8 8b 80 a8 00 00 00 85 c0 74 09 48 8d 1d cf 3d 03 00 eb 07",
                "shutdown": "f3 0f 1e fa 55 48 89 e5 48 83 ec 10 48 8d 05 5c ee ff ff 48 89 c6 48 8d 05 c3 a2 0b 00 48 89 c7 e8 c3 c7 ff ff 85 c0 74 07 b8 ff ff ff ff eb 71 48 8b 05 b9 a2 0b 00 48 89 c7 e8 99 d1 ff ff 8b 05 8f a2 0b 00 85 c0 75 34 48 8b 05 a0 a2 0b 00 48 89 c7 e8 10 df ff ff bf 9a e0 ff ff e8 96 de ff ff b8 ff ff ff ff eb 38 48 8b 05 88 a2 0b 00 be ff ff ff ff 48 89 c7 e8 fb cd ff ff",
                "cleanup": "f3 0f 1e fa 55 48 89 e5 48 83 ec 10 e8 68 07 fd ff 48 89 45 f8 48 8d 05 45 90 01 00 48 8b 00 8b 40 08 83 f8 03 76 14 48 8d 05 0b b7 00 00 48 89 c7 b8 00 00 00 00 e8 be 10 fd ff 48 8b 45 f8 8b 00 83 e0 08 85 c0 75 1e ba 0b 04 00 00 48 8d 05 15 b5 00 00 48 89 c6 48 8d 05 fa b6 00 00 48 89 c7 e8 b3 0f fd ff 48 8b 45 f8 8b 00 83 e0 08 85 c0 0f 84 6b 01 00 00 48 8b 05 4b 91 01 00 48 89 c7 e8 b3 0f fd ff eb 14",
                "abort": "f3 0f 1e fa 55 48 89 e5 53 48 83 ec 38 48 89 7d c8 48 89 75 c0 64 48 8b 04 25 28 00 00 00 48 89 45 e8 31 c0 48 8b 45 c8 0f b6 40 31 83 e0 04 84 c0 75 35 48 8b 45 c8 48 8b 80 78 02 00 00 48 89 c7 e8 7c 45 ff ff 85 c0 7f 1e ba e1 0b 00 00 48 8d 05 ec a4 06 00 48 89 c6 48 8d 05 7a b1 06 00",
                # TLS 1.2
                "derive_secret_12" : "f3 0f 1e fa 55 48 89 e5 48 83 ec 20 48 89 7d f8 48 89 75 f0 48 89 55 e8 48 83 7d f0 00 75 1e ba 30 0e 00 00 48 8d 05 75 93 06 00 48 89 c6 48 8d 05 c9 a1 06 00 48 89 c7 e8 d3 38 ff ff 48 8b 45 f8 0f b6 40 31 83 e0 04 84 c0"       
            }
        },
        "callback_file": "nss_cb_13.py",
        "callback_functions":{
            "derive_secret": "nss_cb_13.derive_secrets_callback",
            "key_update": "nss_cb_13.key_update_callback",
            "shutdown": "nss_cb_13.shutdown_callback",
            "cleanup": "nss_cb_13.cleanup_callback",
            "abort": "nss_cb_13.abort_callback",
            # TLS 1.2
            "derive_secret_12": "nss_cb_13.derive_secrets_callback_12"
        }
    },
    # keyUpdate: tls_process_key_update
    # abort: SSL_read (check for return value <= 0)
    "openssl": {
        "module": "libssl",
        "patterns": {
            "x86_64": { 
                "derive_secret": "41 57 4D 89 CF 41 56 41 89 CE 41 55 4D 89 C5 41 54 49 89 D4 55 48 89 FD 48 89 F7 53 48 89 F3 48 83 EC 08 E8",
                "key_update": "f3 0f 1e fa 55 48 89 fd 48 81 c7 60 0c 00 00 53 48 89 f3 48 83 ec 08 e8 44 82 fd ff 85 c0 0f 85 8c 00 00 00 48 8b 43 08 48 85 c0 74 43 48 8b 13 0f b6 0a 48 83 c2 01 48 83 e8 01 48 89 13 48 89 43 08 75 2c 83 f9 01",
                "shutdown": "f3 0f 1e fa 55 53 48 83 ec 38 64 48 8b 04 25 28 00 00 00 48 89 44 24 28 31 c0 48 85 ff 74 6d 8b 07 48 89 fb 85 c0 75 60 48 89 fd 48 83 7d 70 00 0f 84 41 01 00 00 48 89 df e8 02 a8 07 00 85 c0 0f 85 fc 00 00 00 f6 85 b9 09 00 00 01",
                "cleanup": "f3 0f 1e fa 48 85 ff 0f 84 9b 04 00 00 41 55 b8 ff ff ff ff 41 54 55 53 48 89 fb 48 83 ec 08 f0 0f c1 87 a4 00 00 00 83 e8 01 85 c0 74 12 7e 10 48 83 c4 08 5b 5d 41 5c 41 5d",
                "abort":"f3 0f 1e fa 48 83 ec 18 64 48 8b 04 25 28 00 00 00 48 89 44 24 08 31 c0 85 d2 78 27 48 89 e1 48 63 d2 e8 d9 fd ff ff 85 c0 7e 03 8b 04 24 48 8b 54 24 08 64 48 2b 14 25 28 00 00 00 75 3c 48 83 c4 18 c3",
                # TLS 1.2
                "derive_secret_12": "f3 0f 1e fa 41 57 41 56 49 89 ce 41 55 49 89 d5 41 54 49 89 f4 55 4c 89 c5 53 48 89 fb 48 81 ec 58 02 00 00 64 48 8b 04 25 28 00 00 00 48 89 84 24 48 02 00 00 48 8b 87 00 09 00 00 f6 80 78 03 00 00 01 74 43 be 01 00 00 00"
            }
        },
        "callback_file": "openssl_cb_13.py",
        "callback_functions": {
            "derive_secret": "openssl_cb_13.derive_secrets_callback",
            "key_update": "openssl_cb_13.key_update_callback",
            "shutdown": "openssl_cb_13.shutdown_callback",
            "cleanup": "openssl_cb_13.cleanup_callback",
            "abort": "openssl_cb_13.abort_callback",
            # TLS 1.2
            "derive_secret_12": "openssl_cb_13.derive_secrets_callback_12"
        }
    },
    # key_update: received_key_update_request
    # shutdown: process_alert
    "rustls": {
        "module": "test_client",
        "patterns" : {
            "x86_64": {
                "derive_secret": "48 83 ec 68 4c 89 44 24 30 48 89 4c 24 28 89 d0 48 89 74 24 08 48 89 fa 48 8b 7c 24 08 48 89 54 24 18 88 44 24 17 48 89 54 24 40 48 89 7c 24 48 88 44 24 57 48 89 4c 24 58 4c 89 44 24 60",
                "key_update": "48 83 ec 48 48 89 74 24 08 48 89 7c 24 10 48 89 7c 24 18 48 89 74 24 40 80 7e 02 00 75 41 48 8d 7c 24 20 be 3f 00 00 00 48 8d 15 c9 e9 26 00 ff 15 83 78 28 00 48 8b 44 24 10 48 8b 4c 24 20 48 89 08 48 8b 4c 24 28 48 89 48 08 48 8b 4c 24 30 48 89 48 10 48 8b 4c 24 38 48 89 48 18 eb 17",
                "shutdown": "48 81 ec 18 02 00 00 48 89 74 24 20 48 89 7c 24 28 48 89 7c 24 30 48 89 54 24 38 48 89 b4 24 f8 01 00 00 c6 84 24 f7 01 00 00 00 48 8b 44 24 38 0f b6 00 48 83 f8 02 75 5f 48 8b 74 24 20 48 8b 44 24 38 8a 48 02 8a 40 03 88 4c 24 61 88 44 24 62 c6 44 24 60 0a",
                # TLS 1.2
                "derive_secret_12" : "50 48 89 3c 24 48 83 c7 48 48 8d 35 e0 9d 2f 00 48 8b 05 09 8a 31 00 ff d0 59 c3",
                # this is process_alert (not cleanup)
                "cleanup": "48 81 ec 38 03 00 00 48 89 74 24 20 48 89 7c 24 28 48 89 7c 24 30 48 89 54 24 38 48 89 b4 24 18 03 00 00 c6 84 24 17 03 00 00 00 48 8b 44 24 38 0f b6 00 48 83 f8 02 75 57 48 8b 74 24 20 48 8b 44 24 38 8a 48 02 8a 40 03 88 8c 24 81 00 00 00 88 84 24 82 00 00 00 c6 84 24 80 00 00 00 0a 48 8d 7c 24 40"
            }
        },
        "callback_file": "rustls_cb_13.py",
        "callback_functions": {
            "derive_secret": "rustls_cb_13.derive_secrets_callback",
            "key_update": "rustls_cb_13.key_update_callback",
            "shutdown": "rustls_cb_13.shutdown_callback",
            "cleanup": "rustls_cb_13.cleanup_callback",
            "abort": "rustls_cb_13.abort_callback",
            # TLS 1.2
            "derive_secret_12": "rustls_cb_13.derive_secrets_callback_12"
        }
    },
    # key_update: s2n_update_application_traffic_keys
    # abort: s2n_process_alert_fragment
    "s2ntls": {
        "module": "libs2n",
        "patterns": {
            "x86_64": { 
                "derive_secret": "f3 0f 1e fa 41 57 41 56 41 55 41 54 55 53 48 81 ec 78 02 00 00 89 74 24 0c 48 89 14 24 64 48 8b 04 25 28 00 00 00 48 89 84 24 68 02 00 00 31 c0 48 85 c9 0f 84 01 02 00 00 2e 2e 2e 2e 4d 89 c5 4d 85 c0 0f 84 3a 02 00 00",
                "key_update": "f3 0f 1e fa 2e 2e 2e 2e 41 57 2e 2e 2e 2e 41 56 41 55 41 54 55 53 48 81 ec 98 03 00 00 64 48 8b 04 25 28 00 00 00 48 89 84 24 88 03 00 00 31 c0 48 85 ff 0f 84 c5 04 00 00 48 83 bf e8 00 00 00 00 49 89 fe 0f 84 6b 04 00 00 80 bf db 00 00 00 21 0f",
                "shutdown": "f3 0f 1e fa 2e 2e 41 55 41 54 55 53 48 83 ec 18 64 48 8b 04 25 28 00 00 00 48 89 44 24 08 31 c0 48 85 ff 0f 84 b1 01 00 00 49 89 f5 48 85 f6 0f 84 5c 01 00 00 c7 06 00 00 00 00 48 89 fb e8 8d ae f8 ff 85 c0 0f 88 3c 01 00 00 48 8d bb dc 07 00 00",
                "cleanup": "f3 0f 1e fa 48 83 ec 08 e8 33 f2 f7 ff 48 83 c4 08 c1 f8 1f c3",
                "abort": "f3 0f 1e fa 41 55 41 54 55 53 48 83 ec 08 48 85 ff 0f 84 c0 02 00 00 8b 87 60 07 00 00 48 89 fb 39 87 64 07 00 00 0f 84 5f 02 00 00 2e 2e 2e 2e 2e 8b 87 cc 07 00 00 2e 2e 2e 2b 87 c8 07 00 00 83 f8 02 0f 84 f6 01 00 00 e8 72 54 fd ff 84 c0",
                # TLS 1.2
                "derive_secret_12": "f3 0f 1e fa 41 57 41 56 4d 89 ce 41 55 4d 89 c5 41 54 49 89 cc 55 48 89 f5 53 48 89 fb 48 83 ec 38 48 89 14 24 4c 8b 7c 24 70 4c 89 ff 64 48 8b 04 25 28 00 00 00 48 89 44 24 28 31 c0 e8 8e 36 fa ff 85 c0 0f 88 e6 00 00 00 80 bb db 00 00 00 21"
            }
        },
        "callback_file": "s2n_cb_13.py",
        "callback_functions": {
            "derive_secret": "s2n_cb_13.derive_secrets_callback",
            "key_update": "s2n_cb_13.key_update_callback",
            "shutdown": "s2n_cb_13.shutdown_callback",
            "cleanup": "s2n_cb_13.cleanup_callback",
            "abort": "s2n_cb_13.abort_callback",
            # TLS 1.2
            "derive_secret_12": "s2n_cb_13.derive_secrets_callback_12"
        }
    },
    # key_update: SendTls13KeyUpdate.part.0
    "wolfssl": {
        "module": "libwolfssl",
        "patterns": {
            "x86_64": {
                "derive_secret": "f3 0f 1e fa 41 57 45 89 cf 41 56 49 89 ce 41 55 49 89 f5 41 54 49 89 fc 55 4c 89 c5 53 89 d3 48 83 ec 68 64 48 8b 14 25 28 00 00 00 48 89 54 24 58 31 d2 8b 84 24 a0 00 00 00 83 f8 04",
                "key_update": "53 48 89 fb e8 f7 c3 fd ff 41 b9 16 00 00 00 ba 67 00 00 00 48 89 df c6 00 16 48 89 c6 0f b6 83 c6 02 00 00 41 b8 05 00 00 00 c7 46 02 03 00 05 18 48 8d 4e 05 88 46 01 31 c0 66 89 46 06 c6 46 08 01 66 83 bb f6 03 00 00 00 0f 94 c0 48 83 ec 08 88 46 09 88 83 f6 03 00 00 c6 83 f7 03 00 00 00 6a 00 6a 00 6a 00 e8 74 8d f9 ff 48 83 c4 20",
                "shutdown": "f3 0f 1e fa 48 85 ff 0f 84 d5 00 00 00 53 48 89 fb f6 87 04 04 00 00 08 0f 85 ba 00 00 00 0f b6 87 02 04 00 00 ba ff ff ff ff a8 2c 74 12 83 e0 30 3c 20 74 4b",
                "cleanup": "f3 0f 1e fa 41 54 55 53 48 8d 1d 21 0f 03 00 48 89 df e8 69 52 fa ff 85 c0 0f 85 9c 00 00 00 8b 05 33 0f 03 00 48 89 df 85 c0 0f 8e a0 00 00 00 8b 05 22 0f 03 00 83 e8 01 89 05 19 0f 03 00 8b 05 13 0f 03 00 85 c0 0f 85 83 00 00 00 e8 0e 48 fa ff 83 3d 37 54 03 00 01",
                "abort": "f3 0f 1e fa 85 d2 78 58 41 54 55 48 89 fd 53 48 63 da 48 85 ff 74 39 49 89 f4 48 85 f6 74 31 e8 8c 8c fa ff 31 c9 48 89 da 4c 89 e6 c7 00 00 00 00 00 48 89 ef e8 76 ab ff ff ba ff ff ff ff",
                # TLS 1.2
                "derive_secret_12": "f3 0f 1e fa 41 57 41 56 41 55 41 54 55 89 cd 53 48 89 d3 48 81 ec 98 03 00 00 48 89 7c 24 18 8b 84 24 d0 03 00 00 4c 89 44 24 08 48 8b 8c 24 d8 03 00 00 44 89 4c 24 14 64 48 8b 14 25 28 00 00 00 48 89 94 24 88 03 00 00 31 d2 83 f8 05 0f 84 4c 01 00 00"
            }
        },
        "callback_file": "wolfssl_cb_13.py",
        "callback_functions": {
            "derive_secret": "wolfssl_cb_13.derive_secrets_callback",
            "key_update": "wolfssl_cb_13.key_update_callback",
            "shutdown": "wolfssl_cb_13.shutdown_callback",
            "cleanup": "wolfssl_cb_13.cleanup_callback",
            "abort": "wolfssl_cb_13.abort_callback",
            # TLS 1.2
            "derive_secret_12": "wolfssl_cb_13.derive_secrets_callback_12"
        }
    }
}

import os

# Get the library name from environment variables
current_library = os.environ.get('LLDB_LIBRARY')
print(f"Current library: {current_library}")

# Binary to debug
binary = os.environ.get("LLDB_BINARY")
lib_path = os.environ.get("LLDB_LIB_PATH")

# Get the mode of operation (if needed, though it's unused in the current script)
mode = os.environ.get("LLDB_MODE", None)
abort = "0"
if mode == "abort":
    abort = "1"

protocol_version = os.environ.get("LLDB_PROTOCOL_VERSION", "tls1.3")
print(f"Protocol version: {protocol_version}")

# Name of the module to search for
wanted_module = tls_library_mapping.get(current_library, {}).get("module", None)
print(f"Searching for module: {wanted_module}")

# Patterns to search for in the binary (for now only x86_64 is supported)
current_patterns = tls_library_mapping.get(current_library, {}).get("patterns", {}).get("x86_64", None)
if current_patterns is None:
    print(f"ERROR: No x86_64 patterns found for library '{current_library}'")
    print(f"Available libraries: {list(tls_library_mapping.keys())}")
    sys.stdout.flush()
    sys.exit(1)

derive_secrets_x64 = current_patterns.get("derive_secret", None)
key_update_x64 = current_patterns.get("key_update", None)
shutdown_x64 = current_patterns.get("shutdown", None)
cleanup_x64 = current_patterns.get("cleanup", None)
abort_x64 = current_patterns.get("abort", None)
derive_secrets_x64_tls12 = current_patterns.get("derive_secret_12", None)
cleanup_x64_tls12 = current_patterns.get("cleanup_12", None)

# Callback file and functions
callback_file = tls_library_mapping.get(current_library, {}).get("callback_file", None)
if callback_file is None:
    print(f"ERROR: No callback file found for library '{current_library}'")
    sys.stdout.flush()
    sys.exit(1)

current_functions = tls_library_mapping.get(current_library, {}).get("callback_functions", None)
if current_functions is None:
    print(f"ERROR: No callback functions found for library '{current_library}'")
    sys.stdout.flush()
    sys.exit(1)

callback_function_derive = current_functions.get("derive_secret", None)
callback_function_key_update = current_functions.get("key_update", None)
callback_function_shutdown = current_functions.get("shutdown", None)
callback_function_cleanup = current_functions.get("cleanup", None)
callback_function_abort = current_functions.get("abort", None)
callback_function_derive_tls12 = current_functions.get("derive_secret_12", None)
callback_function_cleanup_tls12 = current_functions.get("cleanup", None)


def find_module(target):
    # Get number of modules
    module_num = target.GetNumModules()
    # Search the right module
    for i in range(module_num):
        module = target.GetModuleAtIndex(i)
        file_spec = module.GetFileSpec()
        module_name = file_spec.GetFilename()

        print(f"Checking module: {module_name}")
        if wanted_module in module_name:
                return module
        
    return None


def get_base_address(target: lldb.SBTarget, module: lldb.SBModule):
    base_addr = module.GetObjectFileHeaderAddress()

    if base_addr.IsValid():
        load_addr = base_addr.GetLoadAddress(target)
        print(f"Module {wanted_module} base address: {load_addr:#x}")
        return load_addr
    else:
        print(f"Failed to get base address for module {wanted_module}")
        return None
    

def calculate_module_size(module: lldb.SBModule):
    # Calculate the total size of the module by summing the sizes of its sections
    num_sections = module.GetNumSections()
    total_size = 0

    for i in range(num_sections):
        section = module.GetSectionAtIndex(i)
        total_size += section.GetByteSize()
    return total_size



def find_masked(mem, pattern, mask):
    print_count = 0;
    for offset in range(len(mem) - len(pattern) + 1):
        for i in range(len(pattern)):
            if mask[i] != 0 and mem[offset + i] != pattern[i]:
                break
        else:
            return offset
    return -1

def find_in_memory(mem, pattern):
    if (len(mem) < len(pattern)):
        return -1
    for i,x in enumerate(mem):
        #print(f"Checking bytes: {mem[i:i+len(pattern)]} against pattern: {pattern}")
        if mem[i:i+len(pattern)] == pattern:
            return i
    return -1

def create_pattern_mask(pattern_bytes):
    """Create a mask for pattern matching, marking variable bytes as 0"""
    mask = bytearray([1] * len(pattern_bytes))
    i = 0
    
    while i < len(pattern_bytes):
        opcode = pattern_bytes[i]
        
        # Handle different instruction types with variable operands
        if opcode == 0xE8:  # CALL rel32
            # Mask the 4-byte relative address
            for j in range(i + 1, min(i + 5, len(pattern_bytes))):
                mask[j] = 0
            i += 5
        elif opcode == 0xE9:  # JMP rel32
            # Mask the 4-byte relative address
            for j in range(i + 1, min(i + 5, len(pattern_bytes))):
                mask[j] = 0
            i += 5
        elif i < len(pattern_bytes) - 1 and pattern_bytes[i:i+2] == b'\x0f\x84':  # JE rel32
            # Mask the 4-byte relative address
            for j in range(i + 2, min(i + 6, len(pattern_bytes))):
                mask[j] = 0
            i += 6
        elif i < len(pattern_bytes) - 1 and pattern_bytes[i:i+2] == b'\x0f\x85':  # JNE rel32
            # Mask the 4-byte relative address  
            for j in range(i + 2, min(i + 6, len(pattern_bytes))):
                mask[j] = 0
            i += 6
        # Add more conditional jumps as needed (0x0f 0x8x series)
        elif i < len(pattern_bytes) - 1 and pattern_bytes[i] == 0x0f and (pattern_bytes[i+1] & 0xF0) == 0x80:
            # Generic conditional jump rel32
            for j in range(i + 2, min(i + 6, len(pattern_bytes))):
                mask[j] = 0
            i += 6
        else:
            i += 1
    
    return mask

def check_for_pattern_in_module(process: lldb.SBProcess, module: lldb.SBModule, module_base_addr, pattern):
    error = lldb.SBError()
    offset = -1

    clean_pattern = pattern.replace(" ", "")
    pattern_bytes = bytes.fromhex(clean_pattern)

    mask = create_pattern_mask(pattern_bytes)

    readable_regions = process.GetMemoryRegions()
    number_of_regions = readable_regions.GetSize()

    for i in range(number_of_regions):
        current_region = lldb.SBMemoryRegionInfo()
        readable_regions.GetMemoryRegionAtIndex(i, current_region)
        
        reagion_base_addr = current_region.GetRegionBase()
        region_end_addr = current_region.GetRegionEnd()
        region_size = region_end_addr - reagion_base_addr

        if reagion_base_addr < module_base_addr:
            #print(f"[DEBUG]Skipping region {i} at {reagion_base_addr:#x} - {region_end_addr:#x} - not within module base address range.")
            continue

        if current_region.IsExecutable() and current_region.IsReadable() and region_size >= len(pattern_bytes):
            description_stream = lldb.SBStream()
            current_region.GetDescription(description_stream)
            description = description_stream.GetData()
            print(f"Description of region {i}: {description}")

            mem = process.ReadMemory(reagion_base_addr, region_size, error)
            if error.Success():
                offset = find_masked(mem, pattern_bytes, mask)
            
                if offset != -1:
                    found_addr = reagion_base_addr + offset
                    print(f"Pattern found at address: {found_addr:#x} in region {reagion_base_addr:#x}")
                    return found_addr
    
    if offset == -1:
        print(f"Pattern {pattern} not found in Memory.")
        sys.stdout.flush()
        return None
    
def process_is_alive(proc: lldb.SBProcess) -> bool:
                            try:
                                if hasattr(proc, "IsAlive"):
                                    return proc.IsAlive()
                                alive_attr = getattr(proc, "is_alive", None)
                                if callable(alive_attr):
                                    return alive_attr()
                                if isinstance(alive_attr, bool):
                                    return alive_attr
                            except Exception:
                                pass
                            st = proc.GetState()
                            return st not in (lldb.eStateDetached, lldb.eStateExited, lldb.eStateInvalid, lldb.eStateCrashed)

def run_until_hit(proc: lldb.SBProcess, bp_id: int):
                                while process_is_alive(proc):
                                    st = proc.GetState()
                                    if st == lldb.eStateStopped:
                                        th = proc.GetSelectedThread()
                                        reason = th.GetStopReason()
                                        if reason == lldb.eStopReasonBreakpoint:
                                            try:
                                                stopped_bp_id = th.GetStopReasonDataAtIndex(0)
                                            except Exception:
                                                stopped_bp_id = -1
                                            if stopped_bp_id == bp_id:
                                                return True
                                        proc.Continue()
                                    elif st in (lldb.eStateRunning, lldb.eStateStepping):
                                        time.sleep(0.01)
                                    else:
                                        break
                                return False   

def run_until_hit(proc: lldb.SBProcess, bp_id: int):
    while process_is_alive(proc):
        st = proc.GetState()
        if st == lldb.eStateStopped:
            th = proc.GetSelectedThread()
            reason = th.GetStopReason()
            if reason == lldb.eStopReasonBreakpoint:
                try:
                    stopped_bp_id = th.GetStopReasonDataAtIndex(0)
                except Exception:
                    stopped_bp_id = -1
                if stopped_bp_id == bp_id:
                    return True
            # auto-continue on everything else
            proc.Continue()
        elif st in (lldb.eStateRunning, lldb.eStateStepping):
            time.sleep(0.01)
        else:
            break
    return False


def continue_until_exit(proc: lldb.SBProcess, *, continue_on_breakpoint: bool = True, continue_on_signal: bool = False):
    """Keep the process running until it exits. Optionally auto-continue on signals (e.g., Go).
    """
    while True:
        if not process_is_alive(proc):
            break
        st = proc.GetState()
        if st == lldb.eStateStopped:
            th = proc.GetSelectedThread()
            reason = th.GetStopReason()
            if reason == lldb.eStopReasonSignal and continue_on_signal:
                proc.Continue()
            elif reason == lldb.eStopReasonBreakpoint and continue_on_breakpoint:
                proc.Continue()
            else:
                # Default: keep going; callbacks will manage any logging
                proc.Continue()
        elif st in (lldb.eStateRunning, lldb.eStateStepping):
            time.sleep(0.01)
        else:
            # Exited/Detached/Crashed, etc.
            break

pattern_name_mapping =  ['derive_secret', 'key_update', 'shutdown', 'cleanup', 'abort', 'derive_secret_12', 'cleanup_12']


def main():
    callback_module = None
    try:
        # Launch lldb
        debugger = lldb.SBDebugger.Create()
        debugger.SetAsync(False)

        target = debugger.CreateTargetWithFileAndArch(binary, lldb.LLDB_ARCH_DEFAULT)
        debugger.HandleCommand("settings set target.process.stop-on-sharedlibrary-events false")
        debugger.HandleCommand("settings set target.process.stop-on-exec false")
        # Don't disable ASLR - avoids "personality set failed" error in Docker
        debugger.HandleCommand("settings set target.disable-aslr false")
        # Ignore common noisy signals so they don't stop the process
        debugger.HandleCommand("process handle -s false -n false -p true SIGPIPE")
        debugger.HandleCommand("process handle -s false -n false -p true SIGUSR1")
        debugger.HandleCommand("process handle -s false -n false -p true SIGUSR2")

        if target:
            # Set a breakpoint at the start of the main function
            main_bp = target.BreakpointCreateByName("main", target.GetExecutable().GetFilename())
            if main_bp.GetNumLocations() < 1:
                print(f"Failed to set breakpoint at main function in {binary}.")
                sys.stdout.flush()

            arch = target.GetTriple()
            print(f"Debugging target: {binary} with architecture: {arch}")
            sys.stdout.flush()

            # Checkout the right pattern
            if arch.startswith("x86_64"):
                patterns = [derive_secrets_x64, key_update_x64, shutdown_x64, cleanup_x64, abort_x64, derive_secrets_x64_tls12, cleanup_x64_tls12]
                callbacks = [callback_function_derive, callback_function_key_update, callback_function_shutdown, callback_function_cleanup, callback_function_abort, callback_function_derive_tls12, callback_function_cleanup_tls12]
            else:
                print("Unsupported architecture! ")
                sys.stdout.flush()
                exit(1)

            # Launch with automatic input
            print(f"Preparing to launch process with library={current_library}, protocol={protocol_version}")
            sys.stdout.flush()
            
            if (current_library in sdl):
                # For these libraries the server will initiate the KeyUpdate, Alerts and shutdown
                # These clients do not need abort input
                if protocol_version == "tls1.3":
                    print(f"Creating launch info with args: [{hostname}, {port}]")
                    launch_info = lldb.SBLaunchInfo([hostname, port])
                elif protocol_version == "tls1.2":
                    print(f"Creating launch info with args: [{hostname}, {port_tls12}]")
                    launch_info = lldb.SBLaunchInfo([hostname, port_tls12])
                else:
                    print(f"Unsupported protocol version {protocol_version} for library {current_library}")
                    sys.stdout.flush()
                    exit(1)
            else:
                print(f"Creating launch info with args: [{hostname}, {port}, {abort}]")
                launch_info = lldb.SBLaunchInfo([hostname, port, abort]) #Arguments for the binary

            launch_flags = launch_info.GetLaunchFlags()
            # Remove the eLaunchFlagDisableASLR flag if present
            launch_flags &= ~lldb.eLaunchFlagDisableASLR
            launch_info.SetLaunchFlags(launch_flags)

            
            print(f"Setting LD_LIBRARY_PATH={lib_path}")
            sys.stdout.flush()
            launch_info.SetEnvironmentEntries([f"LD_LIBRARY_PATH={lib_path}"], True)

            print(f"Launching process: {binary}")
            sys.stdout.flush()
            error = lldb.SBError()
            process = target.Launch(launch_info, error)

            if process and error.Success():
                print(f"[OK] Process launched successfully")
                sys.stdout.flush()
            else:
                print(f"[ERROR] Failed to launch process!")
                print(f"Error: {error.GetCString()}")
                sys.stdout.flush()
                exit(1)

            if process and error.Success():
                print(f"Launched process with PID: {process.GetProcessID()}")
                print(f"Process state: {process.GetState()}")
                sys.stdout.flush()

                watch_num = process.GetNumSupportedHardwareWatchpoints(error)
                print(f"Number of supported hardware watchpoints: {watch_num}")
                sys.stdout.flush()

                state = process.GetState()
                print(f"Process state after launch: {state} (eStateStopped={lldb.eStateStopped})")
                sys.stdout.flush()
                
                if state == lldb.eStateStopped:
                    print("Process is in stopped state, checking thread...")
                    sys.stdout.flush()
                    
                    # Get current thread
                    thread = process.GetSelectedThread()
                    stop_reason = thread.GetStopReason()
                    print(f"Thread stop reason: {stop_reason} (eStopReasonBreakpoint={lldb.eStopReasonBreakpoint}, eStopReasonSignal={lldb.eStopReasonSignal})")
                    sys.stdout.flush()
                    
                    if thread.GetStopReason() == lldb.eStopReasonBreakpoint or (thread.GetStopReason() == lldb.eStopReasonSignal and current_library == "gotls"):
                        print("Hit main function breakpoint.")
                        sys.stdout.flush()
                    else:
                        print(f"WARNING: Process stopped but not at expected breakpoint (reason: {stop_reason})")
                        sys.stdout.flush()
                else:
                    print(f"WARNING: Process is not in stopped state (state={state})")
                    sys.stdout.flush()
                    
                if state == lldb.eStateStopped:
                    # Get current thread
                    thread = process.GetSelectedThread()
                    if thread.GetStopReason() == lldb.eStopReasonBreakpoint or (thread.GetStopReason() == lldb.eStopReasonSignal and current_library == "gotls"):
                        print("Proceeding with breakpoint setup...")
                        sys.stdout.flush()

                        # Add lldb directory to Python path so callback files can import shared module
                        lldb_dir = os.path.abspath("./lldb")
                        if lldb_dir not in sys.path:
                            sys.path.insert(0, lldb_dir)
                            print(f"Added {lldb_dir} to Python path")
                            sys.stdout.flush()

                        # Import callback function - use current working directory or explicit path
                        callback_path = os.path.join("./lldb", callback_file)
                        print(f"Attempting to import callback from: {callback_path}")
                        sys.stdout.flush()
                        
                        # Check if file exists before trying to import
                        if os.path.exists(callback_path):
                            debugger.HandleCommand(f"command script import {callback_path}")
                            mod_name = os.path.splitext(os.path.basename(callback_file))[0]
                            callback_module = importlib.import_module(mod_name)
                        else:
                            print(f"ERROR: Callback file not found at {callback_path}")
                            print(f"Current working directory: {os.getcwd()}")
                            print(f"Files in ./lldb/: {os.listdir('./lldb') if os.path.exists('./lldb') else 'Directory not found'}")
                            sys.stdout.flush()
                            exit(1)
                        
                        # Find the desired module first
                        target_module = find_module(target) if wanted_module != "multiple" else None
                        derive_secrets_bp = None
                        
                        # Process each pattern
                        for i, pattern in enumerate(patterns):
                            if pattern is None or callbacks[i] is None:
                                print(f"Pattern or callback {i} ({pattern_name_mapping[i]}) is None, skipping...")
                                sys.stdout.flush()
                                continue
                                
                            pattern_found = None
                            found_in_module = False
                            
                            # First try to find in the target module if specified and found
                            if target_module and wanted_module != "multiple":
                                base_addr = get_base_address(target, target_module)
                                if base_addr:
                                    print(f"Checking target module: {target_module.GetFileSpec().GetFilename()} for pattern {i}")
                                    pattern_found = check_for_pattern_in_module(process, target_module, base_addr, pattern)
                                    if pattern_found:
                                        found_in_module = True
                                        module_name = target_module.GetFileSpec().GetFilename()
                                        print(f"Pattern {i} found in target module {module_name} at address {pattern_found:#x}")
                            
                            # If not found in target module or no target module, search all modules
                            if not found_in_module:
                                print(f"Pattern {i} not found in target module, searching all modules...")
                                module_num = target.GetNumModules()
                                for j in range(module_num):
                                    module = target.GetModuleAtIndex(j)
                                    module_name = module.GetFileSpec().GetFilename()
                                    
                                    # Skip if this is the target module we already checked
                                    if target_module and module.GetFileSpec().GetFilename() == target_module.GetFileSpec().GetFilename():
                                        continue
                                        
                                    base_addr = get_base_address(target, module)
                                    if base_addr:
                                        print(f"Checking module: {module_name} for pattern {i}")
                                        pattern_found = check_for_pattern_in_module(process, module, base_addr, pattern)
                                        if pattern_found:
                                            print(f"Pattern {i} found in module {module_name} at address {pattern_found:#x}")
                                            break
                            
                            # If pattern found in any module, set a breakpoint
                            if pattern_found:
                                current_breakpoint = target.BreakpointCreateByAddress(pattern_found)
                                if current_breakpoint.GetNumLocations() < 1:
                                    print(f"Failed to set breakpoint at pattern address {pattern_found:#x}.")
                                    sys.stdout.flush()
                                    continue
                                    
                                # Set the script callback function
                                current_breakpoint.SetScriptCallbackFunction(callbacks[i])
                                
                                current_breakpoint.SetEnabled(True)
                                # Irrellevant dumps will be filtered out in post processing
                                #if i > 0:
                                #    current_breakpoint.SetOneShot(True)
                                    
                                description_stream = lldb.SBStream()
                                current_breakpoint.GetDescription(description_stream)
                                description = description_stream.GetData()
                                print(f"Description: {description}")
                                sys.stdout.flush()
                                
                                if i == 0:
                                    derive_secrets_bp = current_breakpoint
                            else:
                                print(f"Pattern {i} not found in any module")
                        
                        # If we have derive_secrets_bp, continue process execution
                        if derive_secrets_bp:
                            process.Continue()
                            hit = run_until_hit(process, derive_secrets_bp.GetID())
                            
                            print(f"Process state after run loop: {process.GetState()}")
                            print(f"Breakpoint hit count: {derive_secrets_bp.GetHitCount()} (hit={hit})")
                            sys.stdout.flush()
                            
                            # For Go (gotls), the process keeps stopping with eStopReasonSignal
                            if current_library == "gotls":
                                print("Continuing process to allow multiple callback hits (Go signals)...")
                                sys.stdout.flush()
                                continue_until_exit(process, continue_on_breakpoint=True, continue_on_signal=True)
                        else:
                            print("No derive_secret pattern found, exiting")
                            sys.stdout.flush()
                            exit(1)
                    else:
                        # If stopped for other reasons (e.g., signals), auto-continue until our breakpoints manage flow
                        print(f"Process stopped for reason: {thread.GetStopReason()} - continuing ...")
                        sys.stdout.flush()
                        process.Continue()
        else:
            print(f"Failed to create target for binary: {binary}")
            sys.stdout.flush()
            exit(1)
    finally:
        print("Process finished. Attempting to write CSV data...")
        if callback_module and hasattr(callback_module, 'logger'):
            try:
                # Explicitly call the write function
                success = callback_module.logger.write_to_csv()
                if success:
                    print("Successfully flushed logger data to CSV.")
                else:
                    print("Logger reported an issue writing to CSV.")
            except Exception as e:
                print(f"An error occurred while writing CSV data: {e}")
        else:
            print("Could not find the logger instance to write data.")

print("Starting main() function...")
sys.stdout.flush()

try:
    main()
    print("main() completed successfully")
    sys.stdout.flush()
except Exception as e:
    import traceback
    print(f"ERROR in main(): {e}")
    print(f"Exception type: {type(e).__name__}")
    print("Full traceback:")
    traceback.print_exc()
    sys.stdout.flush()
    exit(1)
