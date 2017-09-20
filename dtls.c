#include <stdio.h>
#include <stdlib.h>

#include "dtls.h"

void
dtls_Begin()
{
    SSL_library_init();
    SSL_load_error_strings();
    ERR_load_BIO_strings();
    OpenSSL_add_all_algorithms();
}

void
dtls_End()
{
    ERR_remove_state(0);
    ENGINE_cleanup();
    CONF_modules_unload(1);
    ERR_free_strings();
    EVP_cleanup();
    sk_SSL_COMP_free(SSL_COMP_get_compression_methods());
    CRYPTO_cleanup_all_ex_data();
}

static int
_ssl_verify_peer(int ok, X509_STORE_CTX* ctx)
{
    return 1;
}

int
dtls_InitContextFromKeystore(DTLSParams* params, const char* keyname)
{
    int result = 0;

    // Create a new context using DTLS
    params->ctx = SSL_CTX_new(DTLSv1_method());
    if (params->ctx == NULL) {
        printf("Error: cannot create SSL_CTX.\n");
        ERR_print_errors_fp(stderr);
        return -1;
    }

    // Set our supported ciphers
    result = SSL_CTX_set_cipher_list(params->ctx, "ALL:!ADH:!LOW:!EXP:!MD5:@STRENGTH");
    if (result != 1) {
        printf("Error: cannot set the cipher list.\n");
        ERR_print_errors_fp(stderr);
        return -2;
    }

    // The client doesn't have to send it's certificate
    SSL_CTX_set_verify(params->ctx, SSL_VERIFY_PEER, _ssl_verify_peer);

    // Load key and certificate
    char certfile[1024];
    char keyfile[1024];
    sprintf(certfile, "./%s-cert.pem", keyname);
    sprintf(keyfile, "./%s-key.pem", keyname);

    // Load the certificate file; contains also the public key
    result = SSL_CTX_use_certificate_file(params->ctx, certfile, SSL_FILETYPE_PEM);
    if (result != 1) {
        printf("Error: cannot load certificate file.\n");
        ERR_print_errors_fp(stderr);
        return -4;
    }

    // Load private key
    result = SSL_CTX_use_PrivateKey_file(params->ctx, keyfile, SSL_FILETYPE_PEM);
    if (result != 1) {
        printf("Error: cannot load private key file.\n");
        ERR_print_errors_fp(stderr);
        return -5;
    }

    // Check if the private key is valid
    result = SSL_CTX_check_private_key(params->ctx);
    if (result != 1) {
        printf("Error: checking the private key failed. \n");
        ERR_print_errors_fp(stderr);
        return -6;
    }

    return 0;
}

int
dtls_InitClient(DTLSParams* params, const char *address)
{
    params->bio = BIO_new_ssl_connect(params->ctx);
    if (params->bio == NULL) {
        fprintf(stderr, "error connecting to server\n");
        return -1;
    }

    BIO_set_conn_hostname(params->bio, address);
    BIO_get_ssl(params->bio, &(params->ssl));
    if (params->ssl == NULL) {
        fprintf(stderr, "error, exit\n");
        return -1;
    }

    SSL_set_connect_state(params->ssl);
    SSL_set_mode(params->ssl, SSL_MODE_AUTO_RETRY);

    return 0;
}

int
dtls_InitServer(DTLSParams* params)
{
    params->bio = BIO_new_ssl_connect(params->ctx);
    if (params->bio == NULL) {
        fprintf(stderr, "error connecting with BIOs\n");
        return -1;
    }

    BIO_get_ssl(params->bio, &(params->ssl));
    if (params->ssl == NULL) {
        fprintf(stderr, "error, exit\n");
        return -1;
    }

    SSL_set_accept_state(params->ssl);

    return 0;
}

void
dtls_Shutdown(DTLSParams* params)
{
    if (params == NULL) {
        return;
    }

    if (params->ctx != NULL) {
        SSL_CTX_free(params->ctx);
        params->ctx = NULL;
    }

    if (params->ssl != NULL) {
        SSL_free(params->ssl);
        params->ssl = NULL;
    }
}
