/**
 * libssh_kex_hook.c - LD_PRELOAD library for OpenSSH key lifecycle monitoring
 *
 * Comprehensive non-invasive key extraction with memory dumps at critical lifecycle events:
 * - KEX derivation (before/after)
 * - Rekeying events (before/after)
 * - Fork/exec tracking (child process memory dumps)
 * - Session termination (pre/post cleanup dumps)
 *
 * Usage: LD_PRELOAD=/opt/hooks/libssh_kex_hook.so /usr/sbin/sshd -D -e
 *
 * Environment Variables:
 *   HOOK_KEYLOG=/path/to/keylog.log         - Key extraction log
 *   HOOK_EVENTS=/path/to/events.jsonl       - Event timeline (JSON Lines)
 *   HOOK_DUMPS=/path/to/dumps/              - Memory dump directory
 *   HOOK_ENABLE_DUMPS=1                     - Enable full memory dumps
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <dlfcn.h>
#include <pthread.h>
#include <time.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#include <stdint.h>
#include <sys/mman.h>

/* ========================================================================== */
/* CONFIGURATION & GLOBALS */
/* ========================================================================== */

static FILE *g_keylog_file = NULL;
static FILE *g_events_file = NULL;
static FILE *g_debug_log = NULL;  /* Separate debug log instead of stderr */
static char g_dumps_dir[512] = "/data/dumps";
static int g_enable_dumps = 1;
static pthread_mutex_t g_log_mutex = PTHREAD_MUTEX_INITIALIZER;
static int g_initialized = 0;
static int g_kex_counter = 0;
static int g_fork_counter = 0;

/* Debug macro: write to dedicated log file instead of stderr */
#define HOOK_LOG(...) do { \
    if (g_debug_log) { \
        pthread_mutex_lock(&g_log_mutex); \
        fprintf(g_debug_log, __VA_ARGS__); \
        fflush(g_debug_log); \
        pthread_mutex_unlock(&g_log_mutex); \
    } \
} while(0)

/* Function pointers to original functions */
static int (*real_kex_derive_keys)(void *ssh, unsigned char *hash, unsigned int hashlen, const void *shared_secret) = NULL;
static int (*real_kex_send_newkeys)(void *ssh) = NULL;
static pid_t (*real_fork)(void) = NULL;
static void (*real_ssh_packet_close)(void *ssh) = NULL;
static void (*real_cleanup_exit)(int i) = NULL;

/* ========================================================================== */
/* TIMESTAMP UTILITIES */
/* ========================================================================== */

/**
 * Get high-precision timestamp in microseconds since epoch
 */
static uint64_t get_timestamp_us(void) {
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    return (uint64_t)ts.tv_sec * 1000000ULL + (uint64_t)ts.tv_nsec / 1000ULL;
}

/**
 * Format timestamp as ISO 8601 with microseconds
 */
static void format_timestamp(char *buf, size_t bufsize) {
    struct timespec ts;
    struct tm tm;
    clock_gettime(CLOCK_REALTIME, &ts);
    localtime_r(&ts.tv_sec, &tm);

    size_t len = strftime(buf, bufsize, "%Y-%m-%dT%H:%M:%S", &tm);
    snprintf(buf + len, bufsize - len, ".%06ldZ", ts.tv_nsec / 1000);
}

/* ========================================================================== */
/* MEMORY DUMP FUNCTIONALITY */
/* ========================================================================== */

/**
 * Dump full process memory via /proc/self/maps + /proc/self/mem
 * Returns number of regions dumped
 */
static int dump_process_memory(const char *label, pid_t pid) {
    if (!g_enable_dumps) {
        return 0;
    }

    char maps_path[256], mem_path[256], dump_path[512];
    char timestamp_str[32];
    uint64_t timestamp_us = get_timestamp_us();

    /* Use current timestamp for filename */
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    struct tm tm;
    localtime_r(&ts.tv_sec, &tm);
    strftime(timestamp_str, sizeof(timestamp_str), "%Y%m%d_%H%M%S", &tm);

    /* Construct paths */
    if (pid == getpid()) {
        snprintf(maps_path, sizeof(maps_path), "/proc/self/maps");
        snprintf(mem_path, sizeof(mem_path), "/proc/self/mem");
    } else {
        snprintf(maps_path, sizeof(maps_path), "/proc/%d/maps", pid);
        snprintf(mem_path, sizeof(mem_path), "/proc/%d/mem", pid);
    }

    snprintf(dump_path, sizeof(dump_path), "%s/memdump_%s_%s_pid%d.dump",
             g_dumps_dir, timestamp_str, label, pid);

    FILE *maps_file = fopen(maps_path, "r");
    if (!maps_file) {
        HOOK_LOG("[HOOK] Failed to open %s: %s\n", maps_path, strerror(errno));
        return -1;
    }

    int mem_fd = open(mem_path, O_RDONLY);
    if (mem_fd < 0) {
        HOOK_LOG("[HOOK] Failed to open %s: %s\n", mem_path, strerror(errno));
        fclose(maps_file);
        return -1;
    }

    FILE *dump_file = fopen(dump_path, "wb");
    if (!dump_file) {
        HOOK_LOG("[HOOK] Failed to create %s: %s\n", dump_path, strerror(errno));
        close(mem_fd);
        fclose(maps_file);
        return -1;
    }

    /* Write dump header */
    fprintf(dump_file, "# OpenSSH Memory Dump\n");
    fprintf(dump_file, "# PID: %d\n", pid);
    fprintf(dump_file, "# Label: %s\n", label);
    fprintf(dump_file, "# Timestamp: %llu us\n", (unsigned long long)timestamp_us);
    fprintf(dump_file, "# ==================================================\n\n");

    /* Parse /proc/self/maps and dump each readable region */
    char line[512];
    int regions_dumped = 0;

    while (fgets(line, sizeof(line), maps_file)) {
        unsigned long start, end;
        char perms[5];

        /* Parse map line: "address-address perms offset dev inode pathname" */
        if (sscanf(line, "%lx-%lx %4s", &start, &end, perms) != 3) {
            continue;
        }

        /* Only dump readable regions (r---, r-x-, rw--) */
        if (perms[0] != 'r') {
            continue;
        }

        size_t region_size = end - start;

        /* Skip very large regions (> 100MB) to avoid huge dumps */
        if (region_size > 100 * 1024 * 1024) {
            fprintf(dump_file, "# SKIPPED LARGE REGION: %016lx-%016lx %s (size: %zu bytes)\n",
                    start, end, perms, region_size);
            continue;
        }

        /* Allocate buffer for region */
        unsigned char *buf = malloc(region_size);
        if (!buf) {
            HOOK_LOG("[HOOK] Failed to allocate %zu bytes for region %lx-%lx\n",
                    region_size, start, end);
            continue;
        }

        /* Read region from /proc/self/mem */
        ssize_t bytes_read = pread(mem_fd, buf, region_size, start);

        if (bytes_read > 0) {
            fprintf(dump_file, "# Region: %016lx-%016lx %s (size: %zd bytes)\n",
                    start, end, perms, bytes_read);
            fwrite(buf, 1, bytes_read, dump_file);
            fprintf(dump_file, "\n");
            regions_dumped++;
        } else {
            fprintf(dump_file, "# FAILED to read region %016lx-%016lx: %s\n",
                    start, end, strerror(errno));
        }

        free(buf);
    }

    fclose(dump_file);
    close(mem_fd);
    fclose(maps_file);

    HOOK_LOG("[HOOK] Memory dump complete: %s (%d regions)\n", dump_path, regions_dumped);
    return regions_dumped;
}

/* ========================================================================== */
/* EVENT LOGGING (JSON Lines) */
/* ========================================================================== */

/**
 * Log event to JSON Lines file
 */
static void log_event(const char *event_type, const char *details) {
    if (!g_events_file) {
        return;
    }

    pthread_mutex_lock(&g_log_mutex);

    char timestamp[64];
    format_timestamp(timestamp, sizeof(timestamp));

    fprintf(g_events_file, "{\"timestamp\":\"%s\",\"pid\":%d,\"event\":\"%s\",\"details\":\"%s\"}\n",
            timestamp, getpid(), event_type, details);
    fflush(g_events_file);

    pthread_mutex_unlock(&g_log_mutex);
}

/* ========================================================================== */
/* HOOK: kex_derive_keys() - Key Extraction + Memory Dumps */
/* ========================================================================== */

int kex_derive_keys(void *ssh, unsigned char *hash, unsigned int hashlen, const void *shared_secret) {
    /* Load real function if not already loaded */
    if (!real_kex_derive_keys) {
        real_kex_derive_keys = dlsym(RTLD_NEXT, "kex_derive_keys");
        if (!real_kex_derive_keys) {
            HOOK_LOG("[HOOK] Failed to load kex_derive_keys: %s\n", dlerror());
            return -1;
        }
    }

    g_kex_counter++;
    char event_details[256];

    /* Memory dump BEFORE KEX derivation */
    snprintf(event_details, sizeof(event_details), "kex_%d_before", g_kex_counter);
    log_event("KEX_BEFORE", event_details);

    if (g_enable_dumps) {
        char dump_label[64];
        snprintf(dump_label, sizeof(dump_label), "kex_%d_before", g_kex_counter);
        dump_process_memory(dump_label, getpid());
    }

    /* Call original function */
    int result = real_kex_derive_keys(ssh, hash, hashlen, shared_secret);

    /* Extract keys and write to keylog */
    if (result == 0 && hash && hashlen > 0 && hashlen < 1024) {
        pthread_mutex_lock(&g_log_mutex);

        if (g_keylog_file) {
            /* Write cookie (hash) */
            fprintf(g_keylog_file, "# KEX #%d at PID %d\n", g_kex_counter, getpid());
            fprintf(g_keylog_file, "COOKIE ");
            for (unsigned int i = 0; i < hashlen && i < 64; i++) {
                fprintf(g_keylog_file, "%02x", hash[i]);
            }
            fprintf(g_keylog_file, "\n");

            /* Attempt to extract shared secret */
            /* sshbuf structure: u_char *d; size_t off; size_t size; size_t alloc; int readonly; int refcount; */
            if (shared_secret) {
                /* First 8 bytes: pointer to data */
                unsigned char **data_ptr_ptr = (unsigned char **)shared_secret;
                unsigned char *data_ptr = *data_ptr_ptr;

                /* Next 8 bytes: offset */
                size_t *off_ptr = (size_t *)((char *)shared_secret + 8);
                size_t off = *off_ptr;

                /* Next 8 bytes: size */
                size_t *size_ptr = (size_t *)((char *)shared_secret + 16);
                size_t size = *size_ptr;

                if (data_ptr && size > off && (size - off) < 4096) {
                    fprintf(g_keylog_file, "SHARED_SECRET ");
                    for (size_t i = off; i < size && i < (off + 512); i++) {
                        fprintf(g_keylog_file, "%02x", data_ptr[i]);
                    }
                    fprintf(g_keylog_file, "\n");
                }
            }

            fflush(g_keylog_file);
        }

        pthread_mutex_unlock(&g_log_mutex);
    }

    /* Memory dump AFTER KEX derivation */
    snprintf(event_details, sizeof(event_details), "kex_%d_after", g_kex_counter);
    log_event("KEX_AFTER", event_details);

    if (g_enable_dumps) {
        char dump_label[64];
        snprintf(dump_label, sizeof(dump_label), "kex_%d_after", g_kex_counter);
        dump_process_memory(dump_label, getpid());
    }

    return result;
}

/* ========================================================================== */
/* HOOK: kex_send_newkeys() - Rekey Detection */
/* ========================================================================== */

int kex_send_newkeys(void *ssh) {
    /* Load real function */
    if (!real_kex_send_newkeys) {
        real_kex_send_newkeys = dlsym(RTLD_NEXT, "kex_send_newkeys");
        if (!real_kex_send_newkeys) {
            HOOK_LOG("[HOOK] Failed to load kex_send_newkeys: %s\n", dlerror());
            return -1;
        }
    }

    char event_details[256];

    /* Memory dump BEFORE rekey */
    snprintf(event_details, sizeof(event_details), "rekey_%d_before", g_kex_counter + 1);
    log_event("REKEY_BEFORE", event_details);

    if (g_enable_dumps) {
        char dump_label[64];
        snprintf(dump_label, sizeof(dump_label), "rekey_%d_before", g_kex_counter + 1);
        dump_process_memory(dump_label, getpid());
    }

    /* Call original function */
    int result = real_kex_send_newkeys(ssh);

    /* Memory dump AFTER rekey */
    snprintf(event_details, sizeof(event_details), "rekey_%d_after", g_kex_counter + 1);
    log_event("REKEY_AFTER", event_details);

    if (g_enable_dumps) {
        char dump_label[64];
        snprintf(dump_label, sizeof(dump_label), "rekey_%d_after", g_kex_counter + 1);
        dump_process_memory(dump_label, getpid());
    }

    return result;
}

/* ========================================================================== */
/* HOOK: fork() - Child Process Tracking */
/* ========================================================================== */

pid_t fork(void) {
    /* Load real function */
    if (!real_fork) {
        real_fork = dlsym(RTLD_NEXT, "fork");
        if (!real_fork) {
            HOOK_LOG("[HOOK] Failed to load fork: %s\n", dlerror());
            return -1;
        }
    }

    /* Memory dump BEFORE fork (parent perspective) */
    g_fork_counter++;
    char event_details[256];

    snprintf(event_details, sizeof(event_details), "fork_%d_before (parent_pid=%d)",
             g_fork_counter, getpid());
    log_event("FORK_BEFORE", event_details);

    if (g_enable_dumps) {
        char dump_label[64];
        snprintf(dump_label, sizeof(dump_label), "fork_%d_parent_before", g_fork_counter);
        dump_process_memory(dump_label, getpid());
    }

    /* Call original fork */
    pid_t child_pid = real_fork();

    if (child_pid == 0) {
        /* Child process */
        snprintf(event_details, sizeof(event_details), "fork_%d_child (child_pid=%d)",
                 g_fork_counter, getpid());
        log_event("FORK_CHILD", event_details);

        if (g_enable_dumps) {
            char dump_label[64];
            snprintf(dump_label, sizeof(dump_label), "fork_%d_child", g_fork_counter);
            dump_process_memory(dump_label, getpid());
        }
    } else if (child_pid > 0) {
        /* Parent process */
        snprintf(event_details, sizeof(event_details), "fork_%d_parent (child_pid=%d)",
                 g_fork_counter, child_pid);
        log_event("FORK_PARENT", event_details);

        /* Attempt to dump child memory (from parent) */
        if (g_enable_dumps) {
            usleep(50000); /* 50ms delay to let child initialize */
            char dump_label[64];
            snprintf(dump_label, sizeof(dump_label), "fork_%d_child_from_parent", g_fork_counter);
            dump_process_memory(dump_label, child_pid);
        }
    } else {
        /* Fork failed */
        log_event("FORK_FAILED", strerror(errno));
    }

    return child_pid;
}

/* ========================================================================== */
/* HOOK: ssh_packet_close() - Session Termination */
/* ========================================================================== */

void ssh_packet_close(void *ssh) {
    /* Load real function */
    if (!real_ssh_packet_close) {
        real_ssh_packet_close = dlsym(RTLD_NEXT, "ssh_packet_close");
        if (!real_ssh_packet_close) {
            HOOK_LOG("[HOOK] Failed to load ssh_packet_close: %s\n", dlerror());
            return;
        }
    }

    /* Memory dump BEFORE session close */
    log_event("SESSION_CLOSE_BEFORE", "Closing SSH session");

    if (g_enable_dumps) {
        dump_process_memory("session_close_before", getpid());
    }

    /* Call original function */
    real_ssh_packet_close(ssh);

    /* Memory dump AFTER session close */
    log_event("SESSION_CLOSE_AFTER", "SSH session closed");

    if (g_enable_dumps) {
        dump_process_memory("session_close_after", getpid());
    }
}

/* ========================================================================== */
/* HOOK: cleanup_exit() - Process Cleanup */
/* ========================================================================== */

void cleanup_exit(int i) {
    /* Load real function */
    if (!real_cleanup_exit) {
        real_cleanup_exit = dlsym(RTLD_NEXT, "cleanup_exit");
        if (!real_cleanup_exit) {
            HOOK_LOG("[HOOK] Failed to load cleanup_exit: %s\n", dlerror());
            exit(i);
        }
    }

    /* Memory dump BEFORE cleanup */
    char event_details[256];
    snprintf(event_details, sizeof(event_details), "Cleanup exit with code %d", i);
    log_event("CLEANUP_BEFORE", event_details);

    if (g_enable_dumps) {
        dump_process_memory("cleanup_before", getpid());
    }

    /* Call original function (will not return) */
    real_cleanup_exit(i);
}

/* ========================================================================== */
/* LIBRARY INITIALIZATION */
/* ========================================================================== */

__attribute__((constructor))
static void hook_init(void) {
    if (g_initialized) {
        return;
    }

    /* Read configuration from environment */
    const char *keylog_path = getenv("HOOK_KEYLOG");
    const char *events_path = getenv("HOOK_EVENTS");
    const char *dumps_dir = getenv("HOOK_DUMPS");
    const char *enable_dumps_str = getenv("HOOK_ENABLE_DUMPS");
    const char *debug_log_path = getenv("HOOK_DEBUG_LOG");

    /* Set defaults */
    if (!keylog_path) {
        keylog_path = "/data/keylogs/ssh_keylog.log";
    }

    if (!events_path) {
        events_path = "/data/dumps/openssh_events.jsonl";
    }

    if (!debug_log_path) {
        debug_log_path = "/data/dumps/hook_debug.log";
    }

    if (dumps_dir) {
        strncpy(g_dumps_dir, dumps_dir, sizeof(g_dumps_dir) - 1);
    }

    if (enable_dumps_str && strcmp(enable_dumps_str, "0") == 0) {
        g_enable_dumps = 0;
    }

    /* Ensure dumps directory exists */
    mkdir(g_dumps_dir, 0777);

    /* Open debug log FIRST (so HOOK_LOG works) */
    g_debug_log = fopen(debug_log_path, "a");

    /* Open log files */
    g_keylog_file = fopen(keylog_path, "a");
    if (!g_keylog_file) {
        HOOK_LOG("[HOOK] Failed to open keylog: %s\n", keylog_path);
    }

    g_events_file = fopen(events_path, "a");
    if (!g_events_file) {
        HOOK_LOG("[HOOK] Failed to open events log: %s\n", events_path);
    }

    g_initialized = 1;

    HOOK_LOG("[HOOK] LD_PRELOAD library initialized (PID %d)\n", getpid());
    HOOK_LOG("[HOOK]   Keylog:  %s\n", keylog_path);
    HOOK_LOG("[HOOK]   Events:  %s\n", events_path);
    HOOK_LOG("[HOOK]   Debug:   %s\n", debug_log_path);
    HOOK_LOG("[HOOK]   Dumps:   %s (enabled=%d)\n", g_dumps_dir, g_enable_dumps);

    log_event("HOOK_INIT", "LD_PRELOAD library loaded");
}

__attribute__((destructor))
static void hook_fini(void) {
    if (!g_initialized) {
        return;
    }

    log_event("HOOK_FINI", "LD_PRELOAD library unloading");

    HOOK_LOG("[HOOK] LD_PRELOAD library finalized (PID %d)\n", getpid());

    /* Close log files */
    if (g_keylog_file) {
        fclose(g_keylog_file);
        g_keylog_file = NULL;
    }

    if (g_events_file) {
        fclose(g_events_file);
        g_events_file = NULL;
    }

    if (g_debug_log) {
        fclose(g_debug_log);
        g_debug_log = NULL;
    }

    g_initialized = 0;
}
