#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netdb.h>
#include <wolfssl/options.h>
#include <wolfssl/ssl.h>

int main(int argc, char *argv[]) {
    if (argc != 3) {
        printf("Usage %s <hostname> <port> \n", argv[0]);
        return 1;
    }
    const char* hostname = argv[1];
    const char* port = argv[2];
    
    struct addrinfo* res, hints = {};
    int sock = -1;
    int ret = -1;
    WOLFSSL_CTX* ctx;
    WOLFSSL* ssl;
    char buf[1024];
    int n;

    // Resolve hostname
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;
    getaddrinfo(hostname, port, &hints, &res);

    // Create and connect socket
    sock = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
    if (connect(sock, res->ai_addr, res->ai_addrlen) != 0) {
        printf("Unable to TCP connect to server\n");
        goto exit;
    }else{
        printf("Established TCP connection\n");
    }

    // Initialize wolfSSL
    wolfSSL_Init();

    // Create Context
    ctx = wolfSSL_CTX_new(wolfTLSv1_2_client_method());
    if(ctx == NULL){
        printf("Error creating context");
        goto exit;
    }

    // Set the verification mode to none
    wolfSSL_CTX_set_verify(ctx, WOLFSSL_VERIFY_NONE, NULL);


    // Create SSL object
    ssl = wolfSSL_new(ctx);
    if(ssl == NULL){
        printf("Error creating SSL Object");
        goto exit;
    }

    // Set socket
    wolfSSL_set_fd(ssl, sock);

    // Establish TLS-Connection
    if(wolfSSL_connect(ssl) != SSL_SUCCESS){
        printf("Unable to SSL connect to server \n");     
        goto exit;
    }else{
        printf("Established TLS 1.2 connection.\n");
    }

    printf("Waiting for server messages...\n");

    while (1) {
        n = wolfSSL_read(ssl, buf, sizeof(buf)-1);
        if (n > 0) {
            // Received application data
            buf[n] = '\0';
            printf("Received application data: %s\n", buf);
        } else if (n == 0) {
            // Clean connection close (close_notify)
            printf("Received close_notify (clean shutdown by peer).\n");
            ret = 1;
            break;
        } else {
            printf("wolfSSL_read returned error %d\n", n);
            int err = wolfSSL_get_error(ssl, n);
            if (err == WOLFSSL_ERROR_WANT_READ || err == WOLFSSL_ERROR_WANT_WRITE) {
                // Non-fatal, just continue waiting
                continue;
            } else {
                // Error condition
                printf("Protocol error: %d\n", err);
                
                // Check if this is the expected internal error fatal alert
                ret = 0;
                break;
            }
        }
    }

    if (ret != 0) {
        printf("Disconnecting from server...\n");
        wolfSSL_shutdown(ssl);
    }

    ret = 0;

exit:
    // Cleanup
    if(ctx != NULL){
        wolfSSL_CTX_free(ctx);
    }
    wolfSSL_Cleanup();

    if (ret == 0) {
        printf("Disconnected. Process will remain active for 2 seconds before exiting.\n");
        sleep(2);
        printf("Client process exiting.\n");
    }

    return ret;
}