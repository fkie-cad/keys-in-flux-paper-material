#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netdb.h>
#include <errno.h>
#include <gnutls/gnutls.h>
#include <fcntl.h>
#include <poll.h>

// Helper function to check for and print client data without blocking
static void check_client_data(gnutls_session_t session) {
    struct pollfd pfd;
    pfd.fd = gnutls_transport_get_int(session);
    pfd.events = POLLIN;
    
    // Check if data is available (non-blocking)
    if (poll(&pfd, 1, 0) > 0 && (pfd.revents & POLLIN)) {
        char buffer[4096];
        ssize_t bytes = gnutls_record_recv(session, buffer, sizeof(buffer));
        
        if (bytes > 0) {
            printf("Received %zd bytes from client: ", bytes);
            // Print as string if it looks like text, otherwise as hex
            int is_printable = 1;
            for (ssize_t i = 0; i < bytes && is_printable; i++) {
                if (buffer[i] < 32 && buffer[i] != '\n' && buffer[i] != '\r' && buffer[i] != '\t') {
                    is_printable = 0;
                }
            }
            
            if (is_printable) {
                printf("\"");
                fwrite(buffer, 1, bytes, stdout);
                printf("\"\n");
            } else {
                for (ssize_t i = 0; i < bytes; i++) {
                    printf("%02x", (unsigned char)buffer[i]);
                }
                printf("\n");
            }
        } else if (bytes == 0) {
            printf("Client closed connection\n");
        } else if (bytes != GNUTLS_E_AGAIN && bytes != GNUTLS_E_INTERRUPTED) {
            printf("Error receiving data: %s\n", gnutls_strerror((int)bytes));
        }
    }
}

// CSV keylog path and state
static const char *kLogPath = "./keylog.csv";
static FILE *g_keylog_fp = NULL;
static int g_run_id = 0;

// Initialize (or create) the CSV keylog and compute the current run id
static int init_keylog(void) {
    g_keylog_fp = fopen(kLogPath, "a+"); // open for reading and appending
    if (!g_keylog_fp) {
        printf("Unable to open key log file at %s\n", kLogPath);
        return 0;
    }

    // Determine if file is empty
    if (fseek(g_keylog_fp, 0, SEEK_END) != 0) {
        // Best effort continue
    }
    long sz = ftell(g_keylog_fp);

    if (sz <= 0) {
        // New/empty file: write header and start with id 1
        if (fprintf(g_keylog_fp, "id,line\n") < 0) {
            printf("Failed to write CSV header to %s\n", kLogPath);
            return 0;
        }
        fflush(g_keylog_fp);
        g_run_id = 1;
    } else {
        // Existing file: find last id (max id) and increment
        if (fseek(g_keylog_fp, 0, SEEK_SET) != 0) {
            // Fallback if we cannot read: start new id sequence
            g_run_id = 1;
        } else {
            char buf[4096];
            int last_id = 0;
            while (fgets(buf, sizeof(buf), g_keylog_fp)) {
                // Skip header if present
                if (strncmp(buf, "id,", 3) == 0) continue;
                // Trim newline
                char *nl = strchr(buf, '\n');
                if (nl) *nl = '\0';
                // Parse id before first comma
                char *comma = strchr(buf, ',');
                if (!comma) continue;
                *comma = '\0';
                int id = atoi(buf);
                if (id > last_id) last_id = id;
            }
            g_run_id = last_id + 1;
        }
        // Move back to end for appending
        fseek(g_keylog_fp, 0, SEEK_END);
    }

    printf("Keylog run id: %d\n", g_run_id);
    return 1;
}

static void close_keylog(void) {
    if (g_keylog_fp) {
        fclose(g_keylog_fp);
        g_keylog_fp = NULL;
    }
}

int printKeylogCb(gnutls_session_t session, const char* label, const gnutls_datum_t *secret) {
    gnutls_datum_t client_random, server_random;

    // Retrieve the client and server random values
    gnutls_session_get_random(session, &client_random, &server_random);
   
    // Check if the client_random data is valid
    if (client_random.size == 0 || client_random.data == NULL) {
        fprintf(stderr, "Failed to retrieve client random data.\n"); return -1;
    }

    // Format the keylog line similar to NSS_KEYLOG_FORMAT
    printf("%s ", label);

    // Print the client random
    for (size_t i = 0; i < client_random.size; i++) {
        printf("%02x", client_random.data[i]);
    }

    printf(" ");

    // Print the secret
    for (size_t i = 0; i < secret->size; i++) {
        printf("%02x", secret->data[i]);
    }

    printf("\n");
    
    // Append to CSV as "id,line" if keylog file is open
    if (g_keylog_fp && g_run_id > 0) {
        fprintf(g_keylog_fp, "%d,%s ", g_run_id, label);
        
        // Write client random
        for (size_t i = 0; i < client_random.size; i++) {
            fprintf(g_keylog_fp, "%02x", client_random.data[i]);
        }
        
        fprintf(g_keylog_fp, " ");
        
        // Write secret
        for (size_t i = 0; i < secret->size; i++) {
            fprintf(g_keylog_fp, "%02x", secret->data[i]);
        }
        
        fprintf(g_keylog_fp, "\n");
        fflush(g_keylog_fp);
    }

    return 0;
}

int main(int argc, char *argv[]) {
    if (argc != 3) {
        printf("Usage %s <abort> <key_update>\n", argv[0]);
        printf("  abort: 1 to send fatal alert, 0 for clean shutdown\n");
        printf("  key_update: 1 to perform TLS 1.3 key update, 0 to skip\n");
        return 1;
    }
    int abort = atoi(argv[1]);
    int key_update = atoi(argv[2]);
    const char* port = "4433";
    struct addrinfo *res, hints = {};
    int ret = -1;
    int listen_sock = -1;
    int client_sock = -1;
    gnutls_session_t session;
    const char *err;
    int err_code = 0;
    gnutls_certificate_credentials_t xcred;
    gnutls_dh_params_t dh_params;

    const char* cert_file = "../../certs/server.crt";
    const char* key_file = "../../certs/server.key";

    printf("Starting TLS 1.3 server on port %s\n", port);
    
    // Initialize keylog CSV (creates header if needed and sets run id)
    if (!init_keylog()) {
        goto exit;
    }

    // Initialize GnuTLS
    gnutls_global_init();

    // Allocate certificate credentials
    gnutls_certificate_allocate_credentials(&xcred);

    // Load server certificate and private key
    ret = gnutls_certificate_set_x509_key_file(xcred, 
                                               cert_file, 
                                               key_file, 
                                               GNUTLS_X509_FMT_PEM);
    if (ret < 0) {
            printf("Error loading certificate files from relative path: %s\n", gnutls_strerror(ret));
            goto exit;
    }

    // Generate DH parameters
    gnutls_dh_params_init(&dh_params);
    gnutls_dh_params_generate2(dh_params, 2048);
    gnutls_certificate_set_dh_params(xcred, dh_params);

    // Resolve address for binding
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;
    hints.ai_flags = AI_PASSIVE;
    ret = getaddrinfo(NULL, port, &hints, &res);
    if (ret != 0) {
        printf("Error resolving address: %s\n", gai_strerror(ret));
        goto exit;
    }

    // Create and bind listening socket
    listen_sock = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
    if (listen_sock < 0) {
        printf("Error creating socket\n");
        goto exit;
    }

    // Enable socket reuse
    int reuse = 1;
    setsockopt(listen_sock, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse));

    if (bind(listen_sock, res->ai_addr, res->ai_addrlen) != 0) {
        printf("Error binding socket\n");
        goto exit;
    }

    if (listen(listen_sock, 1) != 0) {
        printf("Error listening on socket\n");
        goto exit;
    }

    printf("Server listening on port %s, waiting for connections...\n", port);

    // Accept client connection
    client_sock = accept(listen_sock, NULL, NULL);
    if (client_sock < 0) {
        printf("Error accepting connection\n");
        goto exit;
    }

    printf("Client connected, starting TLS handshake...\n");

    // Initialize TLS session
    if (gnutls_init(&session, GNUTLS_SERVER) != 0) {
        printf("Error initializing TLS session\n");
        goto exit;
    }

    // Set priority and restrict to TLS 1.3
    if (gnutls_priority_set_direct(session, "NORMAL:-VERS-ALL:+VERS-TLS1.3:-CIPHER-ALL:+AES-128-GCM:+CHACHA20-POLY1305", &err) != 0) {
        printf("Error setting priority: %s\n", err);
        goto exit;
    }

    // Set credentials
    gnutls_credentials_set(session, GNUTLS_CRD_CERTIFICATE, xcred);

    // Request client certificate (optional)
    gnutls_certificate_server_set_request(session, GNUTLS_CERT_IGNORE);

    // Set socket descriptor and timeout
    gnutls_transport_set_int(session, client_sock);
    gnutls_handshake_set_timeout(session, GNUTLS_DEFAULT_HANDSHAKE_TIMEOUT);

    // Set the KeyLog Callback (only exports client random)
    gnutls_session_set_keylog_function(session, printKeylogCb);

    // Perform TLS handshake
    err_code = gnutls_handshake(session);
    if (err_code < 0) {
        printf("Error during TLS handshake: %s\n", gnutls_strerror(err_code));
        goto exit;
    }

    printf("TLS handshake completed successfully!\n");
    printf("Protocol: %s\n", gnutls_protocol_get_name(gnutls_protocol_get_version(session)));
    printf("Cipher: %s\n", gnutls_cipher_get_name(gnutls_cipher_get(session)));

    // Check for any client data after handshake
    check_client_data(session);

    const char *app_msg = key_update ? 
                         "SERVER: pre key update\n" : 
                         "SERVER: application data\n";
    ret = gnutls_record_send(session, app_msg, strlen(app_msg));
    if (ret < 0) {
        printf("Failed to send application data: %s\n", gnutls_strerror(ret));
        goto exit;
    } else {
        printf("Server: sent application bytes (%d bytes)\n", ret);
    }
    
    // Check for any client data
    check_client_data(session);

    // Give the client time to process the previous message
    usleep(1000000);

    if (key_update) {
        printf("Sending KeyUpdate message...\n");
        
        // Send a KeyUpdate message
        ret = gnutls_session_key_update(session, GNUTLS_KU_PEER);
        if (ret != GNUTLS_E_SUCCESS) {
            printf("Failed to send KeyUpdate message: %s\n", gnutls_strerror(ret));
            goto exit;
        } else {
            printf("KeyUpdate message sent successfully\n");
    
            check_client_data(session);
    
            // Give the client time to process the KeyUpdate message
            usleep(1000000);
        }
    }
    
    // Send a small application message
    const char *second_msg = key_update ? 
                            "SERVER: key update done\n" : 
                            "SERVER: second message\n";
    ret = gnutls_record_send(session, second_msg, strlen(second_msg));
    if (ret < 0) {
        printf("Failed to send application data: %s\n", gnutls_strerror(ret));
        goto exit;
    } else {
        printf("Server: sent second application message (%d bytes)\n", ret);
    }
    
    // Check for any client data after sending application data
    check_client_data(session);
    
    // Wait for 2 seconds, checking for client data every 200ms
    printf("Waiting for 2 seconds before sending Alert or shutdown...\n");
    for (int i = 0; i < 10; i++) {
        usleep(200000); // 200ms sleep
        check_client_data(session);
    }

    // One final check for client data before sending alert or shutdown
    check_client_data(session);

    if (abort) {    // Send a fatal internal error alert
        printf("Sending fatal internal error alert...\n");
        gnutls_alert_send(session, GNUTLS_AL_FATAL, GNUTLS_A_INTERNAL_ERROR);
        printf("Fatal alert sent\n");
    } else {
        printf("Performing normal shutdown...\n");
        gnutls_bye(session, GNUTLS_SHUT_WR);
    }

    ret = 0;

exit:
    if (session) {
        gnutls_deinit(session);
    }
    if (xcred) {
        gnutls_certificate_free_credentials(xcred);
    }
    if (dh_params) {
        gnutls_dh_params_deinit(dh_params);
    }
    gnutls_global_deinit();
    
    if (client_sock >= 0) {
        close(client_sock);
    }
    if (listen_sock >= 0) {
        close(listen_sock);
    }
    if (res) {
        freeaddrinfo(res);
    }
    
    // Close the keylog file
    close_keylog();

    printf("Server shutting down\n");
    return ret;
}
