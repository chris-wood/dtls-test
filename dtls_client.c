#include "dtls.h"

static void
ssl_client_info_callback(const SSL* ssl, int where, int ret)
{
    ssl_info_callback(ssl, where, ret, "client");
}

int
main(int argc, char *argv[argc])
{
    if (argc < 2) {
        printf("usage: client <message to send to the server>\n");
        exit(-1);
    }

    dtls_begin();

    DTLSParams client;

    if (ssl_ctx_init(&client, "client") < 0) {
        exit(EXIT_FAILURE);
    }
    if (ssl_init(&client, 0, ssl_client_info_callback) < 0) {
        exit(EXIT_FAILURE);
    }

    SSL_connect(client.ssl);

    char buf[521] = { 0 } ;
    snprintf(buf, sizeof(buf), "%s", argv[1]);
    SSL_write(client.ssl, buf, sizeof(buf));

    int read = -1;
    do {
        read = SSL_read(client.ssl, buf, sizeof(buf));
        if (read > 0) {
            printf("IN[%d]: ", read);
            for (int i = 0; i < read; i++) {
                printf("%c", buf[i]);
            }
            printf("\n");
        }
    } while (read < 0);

    ssl_shutdown(&client);
}
