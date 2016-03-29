#include "dtls.h"

#include <stdio.h>
#include <unistd.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

static void
ssl_server_info_callback(const SSL* ssl, int where, int ret)
{
    ssl_info_callback(ssl, where, ret, "server");
}

static int
_createSocket(int port)
{
    int sock;
    struct sockaddr_in addr;

    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = htonl(INADDR_ANY);

    sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        perror("Unable to create socket");
        exit(EXIT_FAILURE);
    }

    if (bind(sock, (struct sockaddr*) &addr, sizeof(addr)) < 0) {
        perror("Unable to bind");
        exit(EXIT_FAILURE);
    }

    if (listen(sock, 1) < 0) {
        perror("Unable to listen");
        exit(EXIT_FAILURE);
    }

    return sock;
}

int
main()
{
    dtls_begin();

    int sock = _createSocket(4433);
    DTLSParams server;

    if (ssl_ctx_init(&server, "server") < 0) {
        exit(EXIT_FAILURE);
    }
    if(ssl_init(&server, 1, ssl_server_info_callback) < 0) {
        exit(EXIT_FAILURE);
    }

    char outbuf[4096];
    while(1) {
        struct sockaddr_in addr;
        uint len = sizeof(addr);
        SSL *ssl;

        int client = accept(sock, (struct sockaddr*) &addr, &len);
        if (client < 0) {
            perror("Unable to accept");
            exit(EXIT_FAILURE);
        }

        SSL_set_fd(server.ssl, client);

        if (SSL_accept(server.ssl) <= 0) {
            ERR_print_errors_fp(stderr);
        } else {
            int read = SSL_read(server.ssl, outbuf, sizeof(outbuf));

            printf("IN[%d]: ", read);
            for (int i = 0; i < read; i++) {
                printf("%c", outbuf[i]);
            }
            printf("\n");

            if (read > 0) {
                SSL_write(server.ssl, outbuf, sizeof(outbuf));
            }
        }

        close(client);
    }

    ssl_shutdown(&server);
}
