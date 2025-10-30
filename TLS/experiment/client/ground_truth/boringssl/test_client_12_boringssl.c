/*
compilation: 
g++ -Iinclude -Ibuild/include -o test_client_12_boringssl test_client_12_boringssl.c build/ssl/libssl.a build/crypto/libcrypto.a -lpthread -ldl

based on https://github.com/openssl/openssl/blob/master/demos/sslecho/main.c
*/

#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <unistd.h>
#include <openssl/ssl.h>
#include <stdio.h>
#include <string.h>
#include <stdbool.h>
#include <errno.h>

int main(int argc, char *argv[]) {
    if (argc != 3) {
        printf("Usage %s <hostname> <port> \n", argv[0]);
        return 1;
    }

    const char* hostname = argv[1];
    const char* port = argv[2];             
    struct addrinfo *res, hints = {};
    int sock = -1;
    SSL_CTX *ctx = NULL;
    SSL *ssl = NULL;
    int ret = 1;  // Default to failure
    char buf[1024];
    int n;

    // Define ssl method and create context
    // Using TLSv1_2_client_method() explicitly to restrict to TLS 1.2 only
    const SSL_METHOD *method = TLSv1_2_client_method();
    ctx = SSL_CTX_new(method);
    
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

    // Link SSL to socket and do handshake
    ssl = SSL_new(ctx);
    if (!ssl) {
        printf("Error creating SSL object\n");
        goto exit;
    }

    SSL_set_fd(ssl, sock);
    if (SSL_connect(ssl) != 1) {
        printf("Unable to SSL connect to server\n");
        goto exit;
    }else{
        printf("Established TLS connection\n");
    }

    printf("Waiting for server messages...\n");

    while (1) {
        n = SSL_read(ssl, buf, sizeof(buf)-1);
        if (n > 0) {
            // Received application data
            buf[n] = '\0';
            printf("Received application data: %s\n", buf);
        } else if (n == 0) {
            // Clean connection close (close_notify)
            printf("Received close_notify (clean shutdown by peer).\n");
            ret = 0;
            break;
        } else {
            int err = SSL_get_error(ssl, n);
            
            if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE) {
                // Non-fatal, just continue waiting
                continue;
            } else {
                // Error condition
                printf("Protocol error: %d\n", err);
                ret = 1;
                break;
            }
        }
    }

    if (ret == 0) {
        printf("Disconnecting from server...\n");
        // SSL_shutdown sends the "close_notify" alert to the other party
        SSL_shutdown(ssl);
    }

    ret = 0;
    
exit:
    // Close connection, clear ssl object and close socket
    if (ssl != NULL) {
        SSL_free(ssl);
    }
    if (ctx != NULL) {
        SSL_CTX_free(ctx);
    }
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
