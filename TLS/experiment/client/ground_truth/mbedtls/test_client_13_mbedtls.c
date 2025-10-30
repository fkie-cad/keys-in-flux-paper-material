#include <mbedtls/net_sockets.h>
#include <mbedtls/ssl.h>
#include <mbedtls/entropy.h>
#include <mbedtls/ctr_drbg.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <unistd.h>

int main(int argc, char *argv[]) {
    if (argc != 3) {
        printf("Usage %s <hostname> <port> \n", argv[0]);
        return 1;
    }
    const char* hostname = argv[1];
    const char* port = argv[2];
    
    struct addrinfo *res, hints = {};
    int sock = -1;
    int ret = -1;
    char buf[1024];
    int n;

    // mbedtls contexts
    mbedtls_ssl_context ssl;
    mbedtls_ssl_config conf;
    mbedtls_net_context server_fd;
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;

    // Initialize mbed TLS contexts
    mbedtls_net_init(&server_fd);
    mbedtls_ssl_init(&ssl);
    mbedtls_ssl_config_init(&conf);
    mbedtls_entropy_init(&entropy);
    mbedtls_ctr_drbg_init(&ctr_drbg);

    // Seed the random number generator
    const char *pers = "ssl_client";
    if((ret = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy, (const unsigned char *)pers, strlen(pers))) != 0) {
        printf("Failed to seed random number generator\n");
        goto exit;
    }

    // Configure TLS settings
    if(mbedtls_ssl_config_defaults(&conf, MBEDTLS_SSL_IS_CLIENT, MBEDTLS_SSL_TRANSPORT_STREAM, MBEDTLS_SSL_PRESET_DEFAULT) != 0){
        printf("Error configuring SSL defaults\n");
        goto exit;
    }

    // Restrict version to TLS 1.3
    mbedtls_ssl_conf_min_version(&conf, MBEDTLS_SSL_MAJOR_VERSION_3, MBEDTLS_SSL_MINOR_VERSION_4);
    mbedtls_ssl_conf_max_version(&conf, MBEDTLS_SSL_MAJOR_VERSION_3, MBEDTLS_SSL_MINOR_VERSION_4);
    

    // disable verification
    mbedtls_ssl_conf_authmode(&conf, MBEDTLS_SSL_VERIFY_NONE);

    mbedtls_ssl_conf_rng(&conf, mbedtls_ctr_drbg_random, &ctr_drbg);

    // Setup and connect
    if(mbedtls_ssl_setup(&ssl, &conf) != 0){
        printf("Error setting up SSL\n");
        goto exit;
    }

    if(mbedtls_net_connect(&server_fd, hostname, port, MBEDTLS_NET_PROTO_TCP) != 0){
        printf("Unable to TCP connect to server\n");
        goto exit;
    }else{
        printf("Established TCP connection\n");
    }

    mbedtls_ssl_set_bio(&ssl, &server_fd, mbedtls_net_send, mbedtls_net_recv, NULL);
    
    // Must be called before handshake 
    psa_crypto_init();

    // negotiate TLS
    if(mbedtls_ssl_handshake(&ssl) != 0){
        printf("Unable to SSL connect to server\n");
        goto exit;
    }
    printf("Established TLS 1.3 connection.\n");

    printf("Waiting for server messages...\n");

    while (1) {
        n = mbedtls_ssl_read(&ssl, (unsigned char*)buf, sizeof(buf)-1);
        if (n > 0) {
            buf[n] = '\0';
            printf("Received application data: %s\n", buf);
        } else if (n == 0 || n == MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY) {
            printf("Received close_notify (clean shutdown by peer).\n");
            ret = 1;
            break;
        } else {
            if (n == MBEDTLS_ERR_SSL_WANT_READ || n == MBEDTLS_ERR_SSL_WANT_WRITE) {
                continue;
            } else {
                printf("Protocol error: %d\n", n);
                ret = 1;
                break;
            }
        }
    }

    if (ret != 0) {
        printf("Disconnecting from server...\n");
        // Send close_notify alert to the other party
        mbedtls_ssl_close_notify(&ssl);
    }

    ret = 0;

exit:
    // Close the connection
    if (ret != 0) {
        mbedtls_ssl_close_notify(&ssl);
    }
    mbedtls_net_free(&server_fd);
    mbedtls_ssl_free(&ssl);
    mbedtls_ssl_config_free(&conf);
    mbedtls_ctr_drbg_free(&ctr_drbg);
    mbedtls_entropy_free(&entropy);

    if (ret == 0) {
        printf("Disconnected. Process will remain active for 2 seconds before exiting.\n");
        sleep(2);
        printf("Client process exiting.\n");
    }

    return ret;
}

