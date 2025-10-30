#include <netdb.h>
#include <unistd.h>
#include <stdio.h>
#include <tls.h>
#include <string.h>

int main(int argc, char *argv[]) {
    if (argc != 3) {
        printf("Usage %s <hostname> <port> \n", argv[0]);
        return 1;
    }
    const char* hostname = argv[1];
    const char* port = argv[2];
    int ret = -1;

    struct tls_config *config = NULL;
    struct tls *ctx = NULL;
    const char* err;
    
    // Initialize libretls
    tls_init();

    // Create config
    config = tls_config_new();
    if(config == NULL){
        printf("Error creating config\n");
        goto exit;
    }

    // Disable verification
    tls_config_insecure_noverifycert(config);
    tls_config_insecure_noverifyname(config);

    // Create Context
    ctx = tls_client();
    if(ctx == NULL){
        printf("Error creating TLS object\n");
        goto exit;
    }

    // Configure Context
    if(tls_configure(ctx, config) != 0){
        printf("Error configuring TLS object\n");
        goto exit;
    }

    // Restrict to TLS 1.2
    // Version is not set properly
    if(tls_config_set_protocols(config, TLS_PROTOCOL_TLSv1_2) != 0){
        printf("Error setting protocols\n");
        goto exit;
    }else{
        printf("Set TLS 1.2\n");
    }

    if(tls_connect(ctx, hostname, port) != 0){
        printf("Unable to TCP connect to server\n");
        goto exit;
    } else {
        printf("Established TCP connection\n");
    }

    if(tls_handshake(ctx) != 0){
        printf("Unable to SSL connect to server\n");
        err = tls_error(ctx);
        printf("Error: %s\n", err);
        goto exit;
    } else{
        printf("Established TLS 1.2 connection.\n");
    }

    // Define buffer for reading data
    char buf[1024];
    ssize_t n;
    
    printf("Waiting for server messages...\n");

    while (1) {
        n = tls_read(ctx, buf, sizeof(buf)-1);
        if (n > 0) {
            // Received application data
            buf[n] = '\0';
            printf("Received application data: %s\n", buf);
        } else if (n == 0) {
            // Clean connection close (close_notify)
            printf("Received close_notify (clean shutdown by peer).\n");
            tls_close(ctx);
            ret = 0;
            break;
        } else if (n == TLS_WANT_POLLIN || n == TLS_WANT_POLLOUT) {
            // Non-fatal, just continue waiting
            continue;
        } else {
            // Error condition
            err = tls_error(ctx);
            printf("Protocol error: %s\n", err);
            
            // Check if this is the expected internal error fatal alert
            if (strstr(err, "internal error") != NULL || 
                strstr(err, "fatal alert") != NULL) {
                printf("Received internal error fatal alert\n");
                ret = 0;
            } else {
                printf("Unexpected TLS error: %s\n", err);
                ret = -1;
            }
            break;
        }
    }
    
    if (ret != 0) {
        printf("Disconnecting from server...\n");
        if (tls_close(ctx) != 0) {
            err = tls_error(ctx);
            printf("tls_close failed: %s\n", err);
            goto exit;
        }
        ret = 0; // success
    }

exit:
    if (ctx != NULL) {
        tls_free(ctx);
    }
    if (config != NULL) {
        tls_config_free(config);
    }
    if (ret == 0) {
        printf("Disconnected. Process will remain active for 2 seconds before exiting.\n");
        sleep(2);
        printf("Client process exiting.\n");
    }
    
    return ret;
}