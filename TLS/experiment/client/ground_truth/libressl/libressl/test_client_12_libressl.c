#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

int main(int argc, char *argv[]) {
    if (argc != 3) {
        printf("Usage %s <hostname> <port>\n", argv[0]);
        return 1;
    }
    const char* host = argv[1];
    const char* port = argv[2];

    SSL* ssl = NULL;
    SSL_CTX* ctx = NULL;
    int sockfd = -1;
    int ret = -1;
    char buf[1024];
    struct addrinfo *res = NULL, hints = {};

    // Create a new SSL context
    ctx = SSL_CTX_new(TLS_client_method());
    if(ctx == NULL){
        printf("SSL_CTX_new failed\n");
        goto exit;
    }

    // Restrict version to TLS 1.2
    SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION);
    SSL_CTX_set_max_proto_version(ctx, TLS1_2_VERSION);

    // Create a new SSL structure
    ssl = SSL_new(ctx);
    if (ssl == NULL){
        printf("SSL_new failed\n");
        goto exit;
    }

    // Resolve hostname
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;
    if (getaddrinfo(host, port, &hints, &res) != 0) {
        printf("Unable to resolve hostname\n");
        goto exit;
    }

    // Create a socket and connect to the server
    sockfd = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
    if(sockfd < 0){
        printf("socket failed\n");
        goto exit;
    }

    if(connect(sockfd, res->ai_addr, res->ai_addrlen) < 0){
        printf("TCP connect failed\n");
        goto exit;
    }else{
        printf("Established TCP connection\n");
    }

    // Associate the socket with the SSL structure
    SSL_set_fd(ssl, sockfd);

    // Perform the TLS handshake
    if(SSL_connect(ssl) <= 0){
        printf("SSL_connect failed\n");
        goto exit;
    }
    printf("Established TLS 1.2 connection.\n");

    // Move variable declarations before any potential goto statements
    int n;
    int err;
    unsigned long error_code;
    char error_string[256];

    printf("Waiting for server messages...\n");

    while (1) {
        n = SSL_read(ssl, buf, sizeof(buf)-1);
        if (n > 0) {
            buf[n] = '\0';
            printf("Received application data: %s\n", buf);
        } else {
            err = SSL_get_error(ssl, n);
            if (err == SSL_ERROR_ZERO_RETURN) {
                printf("Received close_notify (clean shutdown by peer).\n");
                int sd_ret = SSL_shutdown(ssl);
                ret = 0;
                break;
            } else if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE) {
                /* Non-fatal, just continue waiting */
                continue;
            } else if (err == SSL_ERROR_SSL) {
                error_code = ERR_get_error();
                ERR_error_string_n(error_code, error_string, sizeof(error_string));
                printf("Protocol error: %s\n", error_string);
                
                /* Check if this is the expected internal error fatal alert */
                if (strstr(error_string, "internal error") != NULL || 
                    strstr(error_string, "fatal alert") != NULL) {
                    printf("Received internal error fatal alert\n");
                    ret = 0;
                } else {
                    printf("Unexpected SSL error: %s\n", error_string);
                    ret = -1;
                }
                break;
            } else {
                printf("SSL_read failed with error code: %d\n", err);
                break;
            }
        }
    }

    if (ret != 0) {
        printf("Disconnecting from server...\n");
        SSL_shutdown(ssl);
        ret = 0;
    }

exit:
    if (ssl != NULL) {
        SSL_free(ssl);
    }
    if (ctx != NULL) {
        SSL_CTX_free(ctx);
    }
    if (sockfd >= 0) {
        close(sockfd);
    }
    if (res != NULL) {
        freeaddrinfo(res);
    }
    EVP_cleanup();

    if (ret == 0) {
        printf("Disconnected. Process will remain active for 2 seconds before exiting.\n");
        sleep(2);
        printf("Client process exiting.\n");
    }

    return ret;
}