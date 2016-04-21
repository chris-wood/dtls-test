#include "dtls.h"

#include <stdio.h>
#include <unistd.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

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
    // Initialize whatever OpenSSL state is necessary to execute the DTLS protocol.
    dtls_Begin();

    // Create the server UDP listener socket
    int sock = _createSocket(4433);
    DTLSParams server;

    // Initialize the DTLS context from the keystore and then create the server
    // SSL state.
    if (dtls_InitContextFromKeystore(&server, "server") < 0) {
        exit(EXIT_FAILURE);
    }
    if (dtls_InitServer(&server) < 0) {
        exit(EXIT_FAILURE);
    }

    // Loop forever accepting messages from the client, printing their messages,
    // and then terminating their connections
    char outbuf[4096];
    while(true) {
        struct sockaddr_in addr;
        uint len = sizeof(addr);
        SSL *ssl;

        // Accept an incoming UDP packet (connection)
        int client = accept(sock, (struct sockaddr*) &addr, &len);
        if (client < 0) {
            perror("Unable to accept");
            exit(EXIT_FAILURE);
        }

        // Set the SSL descriptor to that of the client socket
        SSL_set_fd(server.ssl, client);

        // Attempt to complete the DTLS handshake
        // If successful, the DTLS link state is initialized internally
        if (SSL_accept(server.ssl) <= 0) {
            ERR_print_errors_fp(stderr);
        } else {
            // Read from the DTLS link
            int read = SSL_read(server.ssl, outbuf, sizeof(outbuf));

            // Print out the client's message
            if (read > 0) {
                printf("IN[%d]: ", read);
                for (int i = 0; i < read; i++) {
                    printf("%c", outbuf[i]);
                }
                printf("\n");

                // Echo the message back to the client
                SSL_write(server.ssl, outbuf, sizeof(outbuf));
            }
        }

        // When done reading the single message, close the client's connection
        // and continue waiting for another.
        close(client);
    }

    // Teardown the link and context state.
    dtls_Shutdown(&server);
}
