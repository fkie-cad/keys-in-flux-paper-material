#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netdb.h>
#include <gnutls/gnutls.h>

int main(int argc, char *argv[]) {
    if (argc != 3) {
        printf("Usage %s <hostname> <port>\n", argv[0]);
        return 1;
    }
    const char* hostname = argv[1];
    const char* port = argv[2];
    
    struct addrinfo *res, hints = {};
    int ret = -1;
    int sock = -1;
    gnutls_session_t session;
    const char *err;
    int err_code = 0;
    gnutls_certificate_credentials_t xcred;
    char buf[1024];
    ssize_t n;

    // Resolve hostname
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;
    getaddrinfo(hostname, port, &hints, &res);


    // Initialize GnuTLS
    gnutls_global_init();
    

    // Initialize session
    if(gnutls_init(&session, GNUTLS_CLIENT) != 0){
        printf("Error initializing session");
        goto exit;
    }

    gnutls_certificate_allocate_credentials(&xcred);
    gnutls_certificate_set_x509_system_trust(xcred);

    // Set priority and restrict to TLS 1.2
    if (gnutls_priority_set_direct(session, "NORMAL:-VERS-ALL:+VERS-TLS1.2", &err) != 0) {
        printf("Error setting priority\n");
        printf("Error: %s\n", err);
        goto exit;
    }
    
     // Create and connect socket
    sock = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
    if (connect(sock, res->ai_addr, res->ai_addrlen) != 0) {
        printf("Unable to TCP connect to server\n");
        goto exit;
    }else{
        printf("Established TCP connection\n");
    }

    // Set socket descriptor and Timeout
    gnutls_transport_set_int(session, sock);
    gnutls_handshake_set_timeout(session, GNUTLS_DEFAULT_HANDSHAKE_TIMEOUT);

    // Set credentials
    gnutls_credentials_set(session, GNUTLS_CRD_CERTIFICATE, xcred);

    // Perform Hanshake
    err_code = gnutls_handshake(session);
    if(err_code < 0){
        printf("Error during handshake");
        printf("Error: %s\n", gnutls_strerror(err_code));
        goto exit;
    }
    printf("Established TLS 1.2 connection.\n");

    printf("Waiting for server messages...\n");

    while (1) {
        n = gnutls_record_recv(session, buf, sizeof(buf)-1);
        if (n > 0) {
            buf[n] = '\0';
            printf("Received application data: %s\n", buf);
        } else if (n == 0) {
            printf("Received close_notify (clean shutdown by peer).\n");
            ret = 1;
            break;
        } else {
            if (n == GNUTLS_E_AGAIN || n == GNUTLS_E_INTERRUPTED) {
                continue;
            } else {
                printf("Protocol error: %d (%s)\n", n, gnutls_strerror(n));
                ret = 1;
                break;
            }
        }
    }

    if (ret != 0) {
        printf("Disconnecting from server...\n");
        // Send close_notify alert to the other party
        gnutls_bye(session, GNUTLS_SHUT_WR);
    }

    ret = 0;

exit:
    gnutls_deinit(session);
    gnutls_certificate_free_credentials(xcred);
    gnutls_global_deinit();
    if (sock >= 0) {
        close(sock);
    }
    if (res != NULL) {
        freeaddrinfo(res);
    }

    if (ret == 0) {
        printf("Disconnected. Process will remain active for 2 seconds before exiting.\n");
        sleep(2);
        printf("Client process exiting.\n");
    }
    
    return ret;
}

