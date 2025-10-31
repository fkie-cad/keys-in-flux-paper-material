/*
 * wolfSSH Client with Robust Explicit Rekeying (updated)
 *
 * Build (example):
 *   cc -g -O0 -Wall -Wextra -o wolfssh_client_rekeyV2 wolfssh_client_rekeyV2.c -lwolfssh -lwolfssl
 */

#include <wolfssh/ssh.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/socket.h>
#include <netdb.h>
#include <fcntl.h>
#include <arpa/inet.h>
#include <netinet/tcp.h>

#define MAX_BUF 4096

/* Options */
static int with_rekey = 0;
static int keep_alive = 0;
static int keep_alive_seconds = 10;
static const char* server_host = NULL;
static int server_port = 22;
static const char* username = NULL;
static const char* password = NULL;

/* Some wolfSSH builds define WS_CHAN_RXD, others WS_CHANNEL_RXD */
#ifndef WS_CHANNEL_RXD
#  ifdef WS_CHAN_RXD
#    define WS_CHANNEL_RXD WS_CHAN_RXD
#  else
#    define WS_CHANNEL_RXD (-1057) /* conservative fallback */
#  endif
#endif

/* Flipped by keying-completion callback if available */
static volatile int g_rekey_done = 0;

/* ---------- utils ---------- */
static void die(const char* msg) { perror(msg); exit(1); }
static void log_err(const char* where, int code) {
    const char* name = wolfSSH_ErrorToName(code);
    fprintf(stderr, "[%s] error: %s (%d)\n", where, name ? name : "UNKNOWN", code);
}

/* ---------- callbacks ---------- */
static int userauth_password_callback(byte authType, WS_UserAuthData* authData, void* ctx) {
    const char* pw = (const char*)ctx;
    if (!authData || authType != WOLFSSH_USERAUTH_PASSWORD || !pw) return WOLFSSH_USERAUTH_FAILURE;
    authData->sf.password.password   = (byte*)pw;
    authData->sf.password.passwordSz = (word32)strlen(pw);
    return WOLFSSH_USERAUTH_SUCCESS;
}
static int public_key_check_callback(const byte* k, word32 sz, void* ctx) {
    (void)k; (void)sz; (void)ctx; return 0; /* accept host key (test only) */
}
/* If your wolfSSH has it, uncomment both lines where this is registered. */
static void on_keying_complete(void* ctx) {
    volatile int* flag = (volatile int*)ctx;
    *flag = 1;
    fprintf(stdout, "[CALLBACK] keying complete\n");
    fflush(stdout);
}

/* ---------- networking ---------- */
static int tcp_connect(const char* host, int port) {
    char portstr[16];
    struct addrinfo hints, *res = NULL, *rp = NULL;
    int sock = -1, rc;

    snprintf(portstr, sizeof(portstr), "%d", port);
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC; hints.ai_socktype = SOCK_STREAM;

    rc = getaddrinfo(host, portstr, &hints, &res);
    if (rc != 0) { fprintf(stderr, "[TCP] %s\n", gai_strerror(rc)); return -1; }

    for (rp = res; rp; rp = rp->ai_next) {
        sock = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
        if (sock < 0) continue;
        if (connect(sock, rp->ai_addr, rp->ai_addrlen) == 0) break;
        close(sock); sock = -1;
    }
    freeaddrinfo(res);
    return sock;
}

/* ---------- rekey driver ---------- */
/* Loop the state machine until rekey finishes (or we time out). */
/* If your build supports the keying-completion callback, wire it and rely on g_rekey_done. */
static int drive_rekey_until_done(WOLFSSH* ssh, int timeout_ms) {
    const int step_ms = 10;
    int waited = 0;
    g_rekey_done = 0;  /* callback (if enabled) will flip this */

    while (waited < timeout_ms) {
        int r = wolfSSH_worker(ssh, NULL);

        /* ✅ Finished: worker OK and callback fired (authoritative) */
        if (r == WS_SUCCESS && g_rekey_done)
            return WS_SUCCESS;

        /* ✅ Keep going on these benign/transient states */
        if (r == WS_REKEYING || r == WS_WANT_READ || r == WS_WANT_WRITE ||
            r == WS_CHANNEL_RXD || r == WS_SUCCESS) {
            usleep(step_ms * 1000);
            waited += step_ms;
            continue;
        }

        /* ❌ Real error: stop */
        if (r < 0)
            return r;
    }

    fprintf(stderr, "[REKEY] timeout waiting for completion\n");
    return WS_FATAL_ERROR;
}


/* ---------- send/recv that tolerate rekey ---------- */
static int send_all(WOLFSSH* ssh, const byte* p, int len) {
    while (len > 0) {
        int r = wolfSSH_stream_send(ssh, (byte*)p, len);
        if (r > 0) { p += r; len -= r; continue; }

        if (r == WS_REKEYING) {
            int d = drive_rekey_until_done(ssh, 10000);
            if (d != WS_SUCCESS) return d;
            continue;
        }
        if (r == WS_WANT_READ || r == WS_WANT_WRITE) { usleep(10000); continue; }

        return r; /* real error */
    }
    return WS_SUCCESS;
}

static int execute_command(WOLFSSH* ssh, const char* cmd) {
    int r = send_all(ssh, (const byte*)cmd, (int)strlen(cmd));
    if (r != WS_SUCCESS) { log_err("send(cmd)", r); return r; }
    r = send_all(ssh, (const byte*)"\n", 1);
    if (r != WS_SUCCESS) { log_err("send(nl)", r); return r; }

    char buf[MAX_BUF];
    int attempts = 0;
    while (attempts < 200) {
        r = wolfSSH_stream_read(ssh, (byte*)buf, sizeof(buf)-1);
        if (r > 0) {
            buf[r] = 0; fputs(buf, stdout);
            if (strstr(buf, "$") || strstr(buf, "#")) break;
            continue;
        }
        if (r == WS_REKEYING) {
            int d = drive_rekey_until_done(ssh, 10000);
            if (d != WS_SUCCESS) { log_err("rekey(read)", d); return d; }
            continue;
        }
        if (r == WS_WANT_READ || r == WS_WANT_WRITE) { usleep(100000); attempts++; continue; }

        log_err("read", r);
        return r;
    }
    return WS_SUCCESS;
}

/* ---------- main ---------- */
int main(int argc, char** argv) {
    WOLFSSH_CTX* ctx = NULL;
    WOLFSSH* ssh = NULL;
    int sock = -1, ret;

    if (argc < 5) {
        fprintf(stderr, "Usage: %s <host> <port> <user> <password> [--with-rekey] [--keep-alive] [--keep-alive-seconds N]\n", argv[0]);
        return 1;
    }

    server_host = argv[1];
    server_port = atoi(argv[2]);
    username    = argv[3];
    password    = argv[4];

    for (int i = 5; i < argc; i++) {
        if (!strcmp(argv[i], "--with-rekey")) with_rekey = 1;
        else if (!strcmp(argv[i], "--keep-alive")) keep_alive = 1;
        else if (!strcmp(argv[i], "--keep-alive-seconds") && i+1 < argc) {
            keep_alive_seconds = atoi(argv[++i]); keep_alive = 1;
        }
    }

    if ((ret = wolfSSH_Init()) != WS_SUCCESS) die("wolfSSH_Init");
    wolfSSH_Debugging_ON();

    ctx = wolfSSH_CTX_new(WOLFSSH_ENDPOINT_CLIENT, NULL);
    if (!ctx) die("wolfSSH_CTX_new");

    wolfSSH_SetUserAuth(ctx, userauth_password_callback);
    wolfSSH_CTX_SetPublicKeyCheck(ctx, public_key_check_callback);
    wolfSSH_SetKeyingCompletionCb(ctx, on_keying_complete);

    sock = tcp_connect(server_host, server_port);
    if (sock < 0) { fprintf(stderr, "[TCP] connect failed\n"); goto cleanup; }

    /* (optional) reduce latency on tiny packets */
    int one = 1;
    setsockopt(sock, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));

    ssh = wolfSSH_new(ctx);
    if (!ssh) die("wolfSSH_new");
    wolfSSH_SetUserAuthCtx(ssh, (void*)password);
    wolfSSH_SetKeyingCompletionCbCtx(ssh, (void*)&g_rekey_done);

    /* Avoid auto-rekey while testing explicit rekey:
       (If you want highwater-based rekey, wire it to call TriggerKeyExchange()
        and handle completion through the same driver path; don’t do both.) */

    ret = wolfSSH_set_fd(ssh, sock);
    if (ret != WS_SUCCESS) { log_err("set_fd", ret); goto cleanup; }
    ret = wolfSSH_SetUsername(ssh, username);
    if (ret != WS_SUCCESS) { log_err("SetUsername", ret); goto cleanup; }

    fprintf(stdout, "[SSH] Handshake + auth...\n");
    ret = wolfSSH_connect(ssh);
    if (ret != WS_SUCCESS) { log_err("connect", ret); goto cleanup; }
    fprintf(stdout, "[SSH] ✓ Connected and authenticated\n");

    /* Allow time for initial KEX to complete */
    sleep(1);

    if (with_rekey) {
        fprintf(stdout, "[REKEY] Trigger...\n");
        ret = wolfSSH_TriggerKeyExchange(ssh);
        if (ret != WS_SUCCESS) { log_err("TriggerKeyExchange", ret); goto cleanup; }

        ret = drive_rekey_until_done(ssh, 15000);
        if (ret != WS_SUCCESS) { log_err("rekey completion", ret); goto cleanup; }
        fprintf(stdout, "[REKEY] ✓ Rekey completed\n");
    }

    /* Keep session alive briefly for key lifecycle observation */
    fprintf(stdout, "[SSH] Session active for %d seconds...\n", 2);
    sleep(2);

    system("touch /tmp/lldb_dump_pre_exit");
    fprintf(stdout, "[SSH] Closing session...\n");

cleanup:
    if (ssh) {
        fprintf(stdout, "[SSH] Calling wolfSSH_free()...\n");
        wolfSSH_free(ssh);
    }
    if (sock >= 0) close(sock);
    if (ctx) {
        fprintf(stdout, "[SSH] Calling wolfSSH_CTX_free()...\n");
        wolfSSH_CTX_free(ctx);
    }
    fprintf(stdout, "[SSH] Calling wolfSSH_Cleanup()...\n");
    wolfSSH_Cleanup();

    /* Keep process alive after cleanup for memory dumps */
    if (keep_alive) {
        fprintf(stdout, "[SSH] Keep-alive: Process staying alive for %d seconds after cleanup...\n", keep_alive_seconds);
        sleep(keep_alive_seconds);
        fprintf(stdout, "[SSH] Keep-alive period completed. Exiting.\n");
    }

    return 0;
}
