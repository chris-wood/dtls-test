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

static void
dtls_check_openssl_version_and_cleanup_thread_state(unsigned long ver)
{
    // OpenSSL >= 1.1.0 final, no need to call ether ERR_remove_thread_state(NULL) or ERR_remove_state(0)
    // OpenSSL >= 1.1.0-pre6 should be the same as OpenSSL >= 1.1.0
    if (ver >= 0x1010000fL) {
        return;
    }
    if (ver >= 0x10100006L) {
        return;
    }

// OpenSSL 1.1.0-pre4/pre5 has a different API prototype (which was later changed back again in pre6)
#if (OPENSSL_VERSION_NUMBER == 0x10100004L || OPENSSL_VERSION_NUMBER == 0x10100005L) && \
    !defined(LIBRESSL_VERSION_NUMBER) && \
    !defined(OPENSSL_IS_BORINGSSL)
    ERR_remove_thread_state();
#endif

// OpenSSL before 1.1.0-pre3 and after 0.9.9(development branch before 1.0.0-pre1 was release)
#if 0x00909000L < OPENSSL_VERSION_NUMBER && \
    OPENSSL_VERSION_NUMBER <= 0x10100003L
    ERR_remove_thread_state(NULL);
#endif

// openssl before 0.9.9-dev(0x00909000)
// must use old API ERR_remove_state(0)
#if (OPENSSL_VERSION_NUMBER <= 0x00909000L) || defined(USE_WOLFSSL) // not tested, but should work...
    ERR_remove_state(0);
#endif
}

void
dtls_End()
{
    dtls_check_openssl_version_and_cleanup_thread_state(OPENSSL_VERSION_NUMBER);
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
