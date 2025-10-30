#include <sys/socket.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <unistd.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(int argc, char *argv[]) {
    if (argc != 3) {
        printf("Usage %s <hostname> <port>\n", argv[0]);
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
    int n, err;
    unsigned long error_code;

    // Define ssl method and create context
    const SSL_METHOD *method = TLS_client_method();
    ctx = SSL_CTX_new(method);

    // Restrict version to TLS 1.2
    SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION);
    SSL_CTX_set_max_proto_version(ctx, TLS1_2_VERSION);

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
    if(!ssl){
        printf("Error creating SSL object\n");
        goto exit;
    }

    SSL_set_fd(ssl, sock);
    if(SSL_connect(ssl) != 1){
        printf("Unable to SSL connect to server\n");
        goto exit;
    }else{
        printf("Established TLS 1.2 connection.\n");
    }

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
                    ret = 1;
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
    // Close connection, clear ssl object and close socket
    if(ssl != NULL){
        SSL_free(ssl);
    }
    if (ctx != NULL) {
        SSL_CTX_free(ctx);
    }
    if (sock >= 0) {
        close(sock);
    }
    ERR_free_strings();

    if (ret == 0) {
        printf("Disconnected. Process will remain active for 2 seconds before exiting.\n");
        sleep(2);
        printf("Client process exiting.\n");
    }
    
    return ret;

}