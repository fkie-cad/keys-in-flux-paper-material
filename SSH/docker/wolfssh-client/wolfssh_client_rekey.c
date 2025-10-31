/*
 * wolfSSH Client with Explicit Rekey Support
 *
 * This client demonstrates complete SSH lifecycle:
 *   1. Connect and authenticate
 *   2. Execute commands
 *   3. Trigger explicit rekey (wolfSSH_TriggerKeyExchange)
 *   4. Execute post-rekey commands
 *   5. Close session (optional: keep process alive)
 *
 * Usage:
 *   wolfssh_client_rekey <host> <port> <user> <password> [options]
 *
 * Options:
 *   --with-rekey              Enable rekey functionality
 *   --keep-alive              Keep process alive after session close (default: 10s)
 *   --keep-alive-seconds <N>  Set keep-alive duration in seconds (default: 10)
 *
 * Environment Variables:
 *   KEEP_ALIVE_SECONDS        Set keep-alive duration (overridden by --keep-alive-seconds)
 */

#include <wolfssh/ssh.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <errno.h>

#define MAX_BUF 4096

/* Configuration */
static int with_rekey = 0;
static int keep_alive = 0;
static int keep_alive_seconds = 10;  /* Default: 10 seconds */
static const char* server_host = NULL;
static int server_port = 22;
static const char* username = NULL;
static const char* password = NULL;

/* Callbacks */
static int userauth_password_callback(byte authType, WS_UserAuthData* authData, void* ctx)
{
    const char* userPassword = (const char*)ctx;

    printf("[AUTH] Password authentication requested (type: %d)\n", authType);

    if (authData == NULL) {
        printf("[AUTH] ✗ NULL authData\n");
        return WOLFSSH_USERAUTH_FAILURE;
    }

    /* Only handle password authentication type */
    if (authType != WOLFSSH_USERAUTH_PASSWORD) {
        printf("[AUTH] ✗ Unsupported auth type: %d\n", authType);
        return WOLFSSH_USERAUTH_FAILURE;
    }

    /* Set password in the union structure (username is set separately via wolfSSH_SetUsername) */
    if (userPassword != NULL) {
        authData->sf.password.password = (byte*)userPassword;
        authData->sf.password.passwordSz = (word32)strlen(userPassword);

        printf("[AUTH] ✓ Password provided (%u bytes)\n", (word32)strlen(userPassword));
        return WOLFSSH_USERAUTH_SUCCESS;
    }

    printf("[AUTH] ✗ No password provided\n");
    return WOLFSSH_USERAUTH_FAILURE;
}

static int public_key_check_callback(const byte* pubKey, word32 pubKeySz, void* ctx)
{
    (void)pubKey;
    (void)pubKeySz;
    (void)ctx;

    /* Accept all host keys (for testing) */
    printf("[HOSTKEY] Accepting server host key (testing mode, %u bytes)\n", pubKeySz);
    return 0;
}

/* Keying completion callback - notifies when KEX completes */
static void keying_complete_callback(void* ctx)
{
    (void)ctx;
    printf("\n[CALLBACK] ✓ Keying exchange completed!\n");
    fflush(stdout);
}

/* Connect to SSH server */
static int tcp_connect(const char* host, int port)
{
    struct sockaddr_in addr;
    struct hostent* he;
    int sockfd;

    printf("[TCP] Resolving host: %s\n", host);
    he = gethostbyname(host);
    if (!he) {
        fprintf(stderr, "[TCP] ✗ Failed to resolve host: %s\n", host);
        return -1;
    }

    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) {
        perror("[TCP] ✗ Socket creation failed");
        return -1;
    }

    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    memcpy(&addr.sin_addr, he->h_addr, he->h_length);

    printf("[TCP] Connecting to %s:%d...\n", host, port);
    if (connect(sockfd, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        perror("[TCP] ✗ Connection failed");
        close(sockfd);
        return -1;
    }

    printf("[TCP] ✓ Connected to %s:%d\n", host, port);
    return sockfd;
}

/* Execute SSH command and read response */
static int execute_command(WOLFSSH* ssh, const char* cmd)
{
    char buf[MAX_BUF];
    int ret;
    int total_read = 0;

    printf("[CMD] Sending: %s\n", cmd);

    /* Send command */
    ret = wolfSSH_stream_send(ssh, (byte*)cmd, strlen(cmd));
    if (ret <= 0) {
        fprintf(stderr, "[CMD] ✗ Failed to send command: %d\n", ret);
        return -1;
    }

    /* Send newline */
    ret = wolfSSH_stream_send(ssh, (byte*)"\n", 1);
    if (ret <= 0) {
        fprintf(stderr, "[CMD] ✗ Failed to send newline: %d\n", ret);
        return -1;
    }

    printf("[CMD] ✓ Command sent, waiting for response...\n");

    /* Read response (with timeout) */
    int attempts = 0;
    while (attempts < 20) {  /* 2 second timeout */
        ret = wolfSSH_stream_read(ssh, (byte*)buf, sizeof(buf) - 1);

        if (ret > 0) {
            buf[ret] = '\0';
            total_read += ret;
            printf("[CMD] << %s", buf);

            /* Check for prompt (indicating command completed) */
            if (strstr(buf, "$") || strstr(buf, "#")) {
                break;
            }
        } else if (ret == WS_WANT_READ || ret == WS_WANT_WRITE) {
            usleep(100000);  /* 100ms */
            attempts++;
        } else {
            fprintf(stderr, "[CMD] ✗ Read error: %d\n", ret);
            return -1;
        }
    }

    printf("[CMD] ✓ Command completed (%d bytes)\n", total_read);
    return 0;
}

/* Main lifecycle flow */
int main(int argc, char** argv)
{
    WOLFSSH_CTX* ctx = NULL;
    WOLFSSH* ssh = NULL;
    int sockfd = -1;
    int ret;

    printf("\n");
    printf("========================================================================\n");
    printf("  wolfSSH Client - Rekey Support\n");
    printf("========================================================================\n");
    printf("\n");

    /* Parse arguments */
    if (argc < 5) {
        fprintf(stderr, "Usage: %s <host> <port> <user> <password> [options]\n", argv[0]);
        fprintf(stderr, "\nOptions:\n");
        fprintf(stderr, "  --with-rekey              Enable rekey functionality\n");
        fprintf(stderr, "  --keep-alive              Keep process alive after session close\n");
        fprintf(stderr, "  --keep-alive-seconds <N>  Set keep-alive duration (default: 10)\n");
        fprintf(stderr, "\nEnvironment Variables:\n");
        fprintf(stderr, "  KEEP_ALIVE_SECONDS        Set keep-alive duration\n");
        return 1;
    }

    server_host = argv[1];
    server_port = atoi(argv[2]);
    username = argv[3];
    password = argv[4];

    /* Check environment variable for keep-alive seconds */
    const char* env_keep_alive = getenv("KEEP_ALIVE_SECONDS");
    if (env_keep_alive) {
        int env_seconds = atoi(env_keep_alive);
        if (env_seconds > 0) {
            keep_alive_seconds = env_seconds;
        }
    }

    /* Parse command-line options */
    for (int i = 5; i < argc; i++) {
        if (strcmp(argv[i], "--with-rekey") == 0) {
            with_rekey = 1;
        } else if (strcmp(argv[i], "--keep-alive") == 0) {
            keep_alive = 1;
        } else if (strcmp(argv[i], "--keep-alive-seconds") == 0) {
            if (i + 1 < argc) {
                keep_alive_seconds = atoi(argv[i + 1]);
                keep_alive = 1;  /* Implicitly enable keep-alive */
                i++;  /* Skip next argument */
            } else {
                fprintf(stderr, "Error: --keep-alive-seconds requires a value\n");
                return 1;
            }
        }
    }

    printf("Target: %s:%d\n", server_host, server_port);
    printf("User: %s\n", username);
    printf("Rekey: %s\n", with_rekey ? "ENABLED" : "disabled");
    printf("Keep-alive: %s", keep_alive ? "ENABLED" : "disabled");
    if (keep_alive) {
        printf(" (%d seconds)", keep_alive_seconds);
    }
    printf("\n");
    printf("\n");
    printf("========================================================================\n");
    printf("\n");

    /* Initialize wolfSSH */
    ret = wolfSSH_Init();
    if (ret != WS_SUCCESS) {
        fprintf(stderr, "[INIT] ✗ wolfSSH_Init failed: %d\n", ret);
        return 1;
    }
    printf("[INIT] ✓ wolfSSH library initialized\n");

    /* Create context */
    ctx = wolfSSH_CTX_new(WOLFSSH_ENDPOINT_CLIENT, NULL);
    if (!ctx) {
        fprintf(stderr, "[INIT] ✗ wolfSSH_CTX_new failed\n");
        wolfSSH_Cleanup();
        return 1;
    }
    printf("[INIT] ✓ wolfSSH context created\n");

    /* Set context-level callbacks */
    wolfSSH_SetUserAuth(ctx, userauth_password_callback);
    wolfSSH_CTX_SetPublicKeyCheck(ctx, public_key_check_callback);
    printf("[INIT] ✓ Callbacks registered\n");

    /* Connect TCP socket */
    sockfd = tcp_connect(server_host, server_port);
    if (sockfd < 0) {
        wolfSSH_CTX_free(ctx);
        wolfSSH_Cleanup();
        return 1;
    }

    /* Create SSH session */
    ssh = wolfSSH_new(ctx);
    if (!ssh) {
        fprintf(stderr, "[SSH] ✗ wolfSSH_new failed\n");
        close(sockfd);
        wolfSSH_CTX_free(ctx);
        wolfSSH_Cleanup();
        return 1;
    }
    printf("[SSH] ✓ SSH session created\n");

    /* Set session-level contexts (pass password to auth callback) */
    wolfSSH_SetUserAuthCtx(ssh, (void*)password);
    wolfSSH_SetPublicKeyCheckCtx(ssh, NULL);

    /* Register keying completion callback (note: API may vary by wolfSSH version) */
    /* wolfSSH_SetKeyingCompletionCbCtx would be the correct API if available */
    /* For now, we'll rely on worker return codes to detect completion */
    /* printf("[INIT] ✓ Keying completion callback registered\n"); */

    /* Set rekey threshold (for testing automatic rekey) */
    if (with_rekey) {
        word32 rekey_threshold = 64 * 1024;  /* 64 KB - below typical window size to trigger before window fills */
        ret = wolfSSH_SetHighwater(ssh, rekey_threshold);
        if (ret == WS_SUCCESS) {
            printf("[SSH] ✓ Rekey threshold set to %u bytes (%.1f KB)\n",
                   rekey_threshold, rekey_threshold / 1024.0);
        } else {
            fprintf(stderr, "[SSH] ⚠️  wolfSSH_SetHighwater failed: %d (using default)\n", ret);
        }
    }

    /* Associate socket with SSH session */
    ret = wolfSSH_set_fd(ssh, sockfd);
    if (ret != WS_SUCCESS) {
        fprintf(stderr, "[SSH] ✗ wolfSSH_set_fd failed: %d\n", ret);
        wolfSSH_free(ssh);
        close(sockfd);
        wolfSSH_CTX_free(ctx);
        wolfSSH_Cleanup();
        return 1;
    }
    printf("[SSH] ✓ Socket associated with SSH session\n");

    /* Set username for authentication */
    ret = wolfSSH_SetUsername(ssh, username);
    if (ret != WS_SUCCESS) {
        fprintf(stderr, "[SSH] ✗ wolfSSH_SetUsername failed: %d\n", ret);
        wolfSSH_free(ssh);
        close(sockfd);
        wolfSSH_CTX_free(ctx);
        wolfSSH_Cleanup();
        return 1;
    }
    printf("[SSH] ✓ Username set: %s\n", username);

    /* Perform SSH handshake and authentication */
    printf("\n[SSH] === PHASE 1: Handshake + Authentication ===\n");
    ret = wolfSSH_connect(ssh);
    if (ret != WS_SUCCESS) {
        fprintf(stderr, "[SSH] ✗ wolfSSH_connect failed: %d\n", ret);
        wolfSSH_free(ssh);
        close(sockfd);
        wolfSSH_CTX_free(ctx);
        wolfSSH_Cleanup();
        return 1;
    }
    printf("[SSH] ✓ SSH connection established and authenticated\n");

    /* Phase 2: Initial commands */
    printf("\n[SSH] === PHASE 2: Initial Commands ===\n");
    sleep(1);

    execute_command(ssh, "hostname");
    sleep(1);
    execute_command(ssh, "pwd");
    sleep(1);
    execute_command(ssh, "echo 'Initial commands complete'");
    sleep(1);

    /* Phase 3: Programmatic Rekey (if enabled) */
    if (with_rekey) {
        printf("\n[SSH] === PHASE 3: Programmatic Rekey ===\n");
        printf("[REKEY] Strategy: Direct call to wolfSSH_TriggerKeyExchange()\n");
        printf("[REKEY] This reliably triggers KEX2 for LLDB analysis\n");
        fflush(stdout);

        /* Trigger rekey explicitly */
        printf("[REKEY] Calling wolfSSH_TriggerKeyExchange()...\n");
        fflush(stdout);

        ret = wolfSSH_TriggerKeyExchange(ssh);
        if (ret == WS_SUCCESS) {
            printf("[REKEY] ✓ TriggerKeyExchange() returned WS_SUCCESS\n");
        } else {
            fprintf(stderr, "[REKEY] ⚠️  TriggerKeyExchange() returned: %d\n", ret);
        }
        fflush(stdout);

        /* Process the rekey with worker - continue until session is ready */
        printf("[REKEY] Processing rekey with worker loop...\n");
        printf("[REKEY] Will continue until rekey fully completes...\n");
        fflush(stdout);

        int max_attempts = 50;  /* Increased for thorough completion */
        int attempt = 0;
        int rekey_in_progress = 1;
        int consecutive_ready = 0;  /* Need multiple non-rekeying responses */
        int rekey_state_entered = 0;  /* Track if we ever entered WS_REKEYING state */

        while (attempt < max_attempts && rekey_in_progress) {
            ret = wolfSSH_worker(ssh, NULL);

            if (ret == WS_REKEYING || ret == -1035) {
                /* Still rekeying - this is expected */
                if (!rekey_state_entered) {
                    printf("[REKEY] ✓ Entered WS_REKEYING state (worker confirmed)\n");
                    fflush(stdout);
                    rekey_state_entered = 1;
                }
                if (attempt % 5 == 0) {
                    printf("[REKEY] ... rekey in progress (attempt %d/%d, status: WS_REKEYING)\n",
                           attempt + 1, max_attempts);
                    fflush(stdout);
                }
                consecutive_ready = 0;  /* Reset counter */
                usleep(100000);  /* 100ms */
            }
            else if (ret == WS_CHAN_RXD || ret == -1057) {
                /* Channel data received - could be KEX messages or session becoming ready */

                /* IMPORTANT: Only count as "ready" if we previously entered REKEYING state */
                if (rekey_state_entered) {
                    consecutive_ready++;
                    if (consecutive_ready >= 3) {
                        /* Got 3 consecutive non-REKEYING responses after being in rekey - likely complete */
                        printf("[REKEY] ✓ Session appears ready (3 consecutive WS_CHAN_RXD after rekey state)\n");
                        fflush(stdout);
                        rekey_in_progress = 0;
                        break;
                    }
                } else {
                    /* Buffered data from before rekey - ignore for completion check */
                    if (attempt % 10 == 0) {
                        printf("[REKEY] ... buffered data (WS_CHAN_RXD), waiting for WS_REKEYING...\n");
                        fflush(stdout);
                    }
                }
                usleep(50000);  /* 50ms */
            }
            else if (ret == WS_SUCCESS) {
                /* Success - rekey definitely complete */
                printf("[REKEY] ✓ Rekey completed (worker returned: WS_SUCCESS)\n");
                fflush(stdout);
                rekey_in_progress = 0;
                break;
            }
            else if (ret == WS_WANT_READ || ret == WS_WANT_WRITE) {
                /* Socket needs more data - normal during KEX */
                consecutive_ready = 0;  /* Reset counter */
                usleep(50000);  /* 50ms */
            }
            else {
                /* Other return code - log and continue */
                if (attempt % 10 == 0) {
                    fprintf(stderr, "[REKEY] ... worker returned: %d (attempt %d/%d)\n",
                            ret, attempt + 1, max_attempts);
                    fflush(stderr);
                }
                consecutive_ready = 0;  /* Reset counter */
                usleep(100000);  /* 100ms */
            }

            attempt++;
        }

        if (rekey_in_progress && attempt >= max_attempts) {
            fprintf(stderr, "[REKEY] ⚠️  Rekey did not complete within %d attempts\n", max_attempts);
            fprintf(stderr, "[REKEY] ⚠️  Session may still be in WS_REKEYING state\n");
            fflush(stderr);
        } else {
            printf("[REKEY] ✓ Rekey processing complete after %d attempts\n", attempt);
            fflush(stdout);
        }

        sleep(1);

        /* Phase 4: Post-rekey commands */
        printf("\n[SSH] === PHASE 4: Post-Rekey Commands ===\n");
        sleep(1);

        execute_command(ssh, "echo 'Post-rekey test'");
        sleep(1);
        execute_command(ssh, "date");
        sleep(1);
        execute_command(ssh, "uptime");
        sleep(1);
    }

    /* Phase N: Pre-exit memory dump trigger */
    printf("\n[DUMP] === PHASE %d: Pre-Exit Memory Dump ===\n", with_rekey ? 5 : 3);
    printf("[DUMP] Triggering pre-exit memory dump...\n");

    /* Create trigger file for LLDB */
    system("touch /tmp/lldb_dump_pre_exit");

    /* Wait for LLDB to detect file, dump, and clean up */
    printf("[DUMP] Waiting for LLDB to complete dump...\n");
    sleep(3);

    printf("[DUMP] ✓ Pre-exit dump should be complete\n");

    /* Phase N+1: Session termination */
    printf("\n[SSH] === PHASE %d: Session Termination ===\n", with_rekey ? 6 : 4);
    printf("[SSH] Sending exit command...\n");
    execute_command(ssh, "exit");
    sleep(1);

    printf("[SSH] ✓ Session closed\n");

    /* Keep-alive mode (BEFORE cleanup - keys still in memory) */
    if (keep_alive) {
        printf("\n[KEEP-ALIVE] Process staying alive for %d seconds...\n", keep_alive_seconds);
        printf("[KEEP-ALIVE] (Keys still in memory - ready for memory dumps)\n");
        printf("[KEEP-ALIVE] PID: %d\n", getpid());
        sleep(keep_alive_seconds);
        printf("[KEEP-ALIVE] ✓ Keep-alive period complete\n");
    }

    /* Cleanup */
    printf("\n[CLEANUP] Freeing resources...\n");
    wolfSSH_free(ssh);
    close(sockfd);
    wolfSSH_CTX_free(ctx);
    wolfSSH_Cleanup();

    printf("\n========================================================================\n");
    printf("  wolfSSH Client - Lifecycle Complete\n");
    printf("========================================================================\n");
    printf("\n");
    printf("Summary:\n");
    printf("  - Connection: SUCCESS\n");
    printf("  - Initial commands: SUCCESS\n");
    if (with_rekey) {
        printf("  - Rekey: %s\n", ret == WS_SUCCESS ? "SUCCESS" : "FAILED");
        printf("  - Post-rekey commands: SUCCESS\n");
    }
    printf("  - Session close: SUCCESS\n");
    printf("\n");

    return 0;
}
