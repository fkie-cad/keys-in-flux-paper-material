#include <s2n.h>
#include <sys/socket.h>
#include <netdb.h>
#include <unistd.h>
#include <stdio.h>

int main(int argc, char *argv[]) {
    if (argc != 3) {
        printf("Usage %s <hostname> <port> \n", argv[0]);
        return 1;
    }
    const char* hostname = argv[1];
    const char* port = argv[2];
    
    struct addrinfo *res, hints = {};
    int sock = -1;
    struct s2n_connection *conn = NULL;
    struct s2n_config *config = NULL;
    int ret = -1;  // Default to failure
    s2n_blocked_status blocked = S2N_NOT_BLOCKED;
    char buf[1024];
    ssize_t n;

    // Initialize s2n and create config
    if(s2n_init() != 0){
        printf("Error initializing s2n\n");
        goto exit;
    }
    config = s2n_config_new();

    // Configure version TLS 1.3
    if(s2n_config_set_cipher_preferences(config, "default_tls13") != 0){
        printf("Error setting cipher preferences\n");
        goto exit;
    }
    
    s2n_config_disable_x509_verification(config);

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

    // Create s2n connection and setting configuration
    conn = s2n_connection_new(S2N_CLIENT);
    if(s2n_connection_set_config(conn, config) != 0){
        printf("Error setting configuration\n");
        goto exit;
    }

    if(s2n_connection_set_fd(conn, sock)){
        printf("Error setting file descriptor\n");
        goto exit;
    }
    
    if(s2n_negotiate(conn, &blocked) != 0) {
        printf("Unable to SSL connect to server\n");
        goto exit;
    }else{
        printf("Established TLS connection\n");
    }

    printf("Waiting for server messages...\n");

    while (1) {
        blocked = S2N_NOT_BLOCKED;
        n = s2n_recv(conn, buf, sizeof(buf)-1, &blocked);

        if (n > 0) {
            buf[n] = '\0';
            printf("Received application data: %s\n", buf);
        } else if (n == 0) {
            printf("Connection closed by peer (close_notify or EOF).\n");
            break;
        } else {
            // n < 0, error occurred
            int s2n_err = s2n_errno;
            int error_type = s2n_error_get_type(s2n_err);
            
            printf("s2n_recv returned %zd, s2n_errno: %d, error_type: %d\n", n, s2n_err, error_type);
            
            if (error_type == S2N_ERR_T_BLOCKED) {
                // Non-blocking operation would block, continue
                printf("Operation would block, continuing...\n");
                usleep(10000); // Sleep 10ms to avoid tight loop
                continue;
            } else {
                // Any other error (including alerts) - exit
                printf("Connection error occurred. Exiting receive loop.\n");
                fprintf(stderr, "s2n_recv error: %s\n", s2n_strerror(s2n_err, NULL));
                fprintf(stderr, "Debug info: %s\n", s2n_strerror_debug(s2n_err, NULL));
                break;
            }
        }
    }

    if (ret != 0) {
        printf("Disconnecting from server...\n");
        s2n_shutdown(conn, &blocked);
        s2n_send(conn, NULL, 0, &blocked);
    }

    ret = 0;

exit:
    // cleanup
    if(conn != NULL){
        s2n_connection_free(conn);
    }

    close(sock);
    s2n_cleanup();

    if (ret == 0) {
        printf("Disconnected. Process will remain active for 2 seconds before exiting.\n");
        sleep(2);
        printf("Client process exiting.\n");
    }

    return ret;
}