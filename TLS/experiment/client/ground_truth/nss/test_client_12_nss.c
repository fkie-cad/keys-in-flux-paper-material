#define SSL_LIBRARY_VERSION_TLS_1_2 0x0303

#include <sys/socket.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <unistd.h>
#include <stdio.h>
#include <nss/nss.h>
#include <nss/ssl.h>
#include <prnetdb.h>
#include <prio.h>
#include <prerror.h>
#include <nspr.h>
#include <string.h>

SECStatus acceptAllCerts(void* arg, PRFileDesc* fd, PRBool checksig, PRBool isServer){
    return SECSuccess;
}

int main(int argc, char *argv[]) {
    if (argc != 3) {
        printf("Usage %s <hostname> <port> \n", argv[0]);
        return 1;
    }
    const char* hostname = argv[1];
    const char* port = argv[2];
    
    struct addrinfo *res, hints = {};
    int ret = -1;
    PRFileDesc* nss_socket = NULL;
    PRFileDesc* tcp_sock = NULL;
    char buf[1024];

    SSLVersionRange version_range;
    version_range.min = SSL_LIBRARY_VERSION_TLS_1_2;
    version_range.max = SSL_LIBRARY_VERSION_TLS_1_2;

    // Initialize NSS
    if (NSS_NoDB_Init(NULL) != SECSuccess) {
        fprintf(stderr, "NSS initialization failed.\n");
        return 1;
    }

    // Initialize NSPR
    PR_Init(PR_SYSTEM_THREAD, PR_PRIORITY_NORMAL, 0);

    // Resolve hostname
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;
    getaddrinfo(hostname, port, &hints, &res);

    // Create and connect socket using NSPR
    tcp_sock = PR_OpenTCPSocket(res->ai_family);
    if (tcp_sock == NULL) {
        printf("Unable to create TCP socket\n");
        goto exit;
    }

    // TCP Connect to Server - use resolved address from getaddrinfo
    PRNetAddr addr;
    memset(&addr, 0, sizeof(addr));
    addr.inet.family = PR_AF_INET;
    struct sockaddr_in *ipv4 = (struct sockaddr_in *)res->ai_addr;
    addr.inet.ip = ipv4->sin_addr.s_addr;
    addr.inet.port = ipv4->sin_port;

    if (PR_Connect(tcp_sock, &addr, PR_INTERVAL_NO_TIMEOUT) != PR_SUCCESS) {
        printf("Unable to TCP connect to server\n");
        goto exit;
    } else {
        printf("Established TCP connection\n");
    }

    // Import the socket into NSS
    nss_socket = SSL_ImportFD(NULL, tcp_sock);
    if (nss_socket == NULL) {
        printf("Unable to import TCP socket to NSS\n");
        goto exit;
    }

    // Restrict TLS version to 1.2
    if (SSL_VersionRangeSet(nss_socket, &version_range) != SECSuccess) {
        printf("Unable to set TLS version range");
        goto exit;
    }

    // Set our own certificate verification function to accept the servers Certificate
    if (SSL_AuthCertificateHook(nss_socket, acceptAllCerts, NULL) != SECSuccess) {
        printf("Unable to set certificate verification function\n");
        goto exit;
    }
    
    // Reset Handshake
    if (SSL_ResetHandshake(nss_socket, 0) != SECSuccess) {
        printf("Unable to reset handshake\n");
        goto exit;
    }

    // Perform Handshake
    if(SSL_ForceHandshake(nss_socket) != SECSuccess){
        printf("Unable to force handshake\n");
        printf("Error message: %s\n", PR_ErrorToString(PR_GetError(), 0));
        goto exit;
    }

    printf("Established TLS 1.2 connection.\n");

    printf("Waiting for server messages...\n");
    while (1) {
        PRInt32 n = PR_Recv(nss_socket, buf, sizeof(buf) - 1, 0, PR_INTERVAL_NO_TIMEOUT);
        if (n > 0) {
            buf[n] = '\0';
            printf("Received application data: %s\n", buf);
        } else if (n == 0) {
            // Clean connection close (close_notify)
            printf("Received close_notify (clean shutdown by peer).\n");
            ret = 0;
            break;
        } else { // n < 0
            // Error condition
            PRErrorCode perr = PR_GetError();
            const char* err_name = PR_ErrorToName(perr);
            const char* err_str = PR_ErrorToString(perr, 0);
            if (!err_name) err_name = "";
            if (!err_str) err_str = "";

            printf("Protocol error: %s (%s)\n", err_str, err_name);

            // Treat internal error / fatal alert related issues as expected
            if (strstr(err_str, "internal error") != NULL ||
                strstr(err_str, "fatal alert") != NULL ||
                strstr(err_name, "SSL_ERROR_CLOSE_NOTIFY") != NULL) {
                printf("Received alert\n");
                ret = 0;
            } else {
                printf("Unexpected TLS error: %s\n", err_str);
                ret = -1;
            }
            break;
        }
    }

    printf("Disconnecting from server...\n");

exit:
    // Close connection and close socket
    if (nss_socket != NULL) {
        PR_Close(nss_socket);
    }
    if (res != NULL) {
        freeaddrinfo(res);
    }
    SSL_ClearSessionCache();
    NSS_Shutdown();
    PR_Cleanup();
    
    if (ret == 0) {
        printf("Disconnected. Process will remain active for 2 seconds before exiting.\n");
        sleep(2);
        printf("Client process exiting.\n");
    }
    
    return ret;
}