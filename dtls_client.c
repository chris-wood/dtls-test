#include "dtls.h"

#define IP_ADDRESS "127.0.0.1:4433"

int
main(int argc, char *argv[argc])
{
    if (argc < 2) {
        printf("usage: client <path to file to send>\n");
        exit(-1);
    }

    // Initialize whatever OpenSSL state is necessary to execute the DTLS protocol.
    dtls_Begin();

    DTLSParams client;

    // Initialize the DTLS context from the keystore and then create the server
    // SSL state.
    if (dtls_InitContextFromKeystore(&client, "client") < 0) {
        exit(EXIT_FAILURE);
    }
    if (dtls_InitClient(&client, IP_ADDRESS) < 0) {
        exit(EXIT_FAILURE);
    }

    // Attempt to connect to the server and complete the handshake.
    int result = SSL_connect(client.ssl);
    if (result != 1) {
        perror("Unable to connect to the DTLS server.\n");
        exit(EXIT_FAILURE);
    }

    // Read the contents of the file (up to 4KB) into a buffer
    FILE *fp = fopen(argv[1], "rb");
    uint8_t buffer[4096] = { 0 };
    size_t numRead = fread(buffer, 1, 4096, fp);

    // Write the buffer to the server
    int written = SSL_write(client.ssl, buffer, numRead);
    if (written != numRead) {
        perror("Failed to write the entire buffer.\n");
        exit(EXIT_FAILURE);
    }

    int read = -1;
    do {
        // Read the output from the server. If it's not empty, print it.
        read = SSL_read(client.ssl, buffer, sizeof(buffer));
        if (read > 0) {
            printf("IN[%d]: ", read);
            for (int i = 0; i < read; i++) {
                printf("%c", buffer[i]);
            }
            printf("\n");
        }
    } while (read < 0);

    // Teardown the link and context state.
    dtls_Shutdown(&client);
}
