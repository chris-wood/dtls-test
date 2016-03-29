#include <stdio.h>
#include <stdlib.h>

#include "dtls.h"

#define SSL_WHERE_INFO(ssl, w, flag, msg) {                \
    if(w & flag) {                                         \
      printf("+ %s: ", name);                              \
      printf("%20.20s", msg);                              \
      printf(" - %30.30s ", SSL_state_string_long(ssl));   \
      printf(" - %5.10s ", SSL_state_string(ssl));         \
      printf("\n");                                        \
    }                                                      \
  }

void
dtls_begin()
{
    SSL_library_init();
    SSL_load_error_strings();
    ERR_load_BIO_strings();
    OpenSSL_add_all_algorithms();
}

void
dtls_end()
{
    ERR_remove_state(0);
    ENGINE_cleanup();
    CONF_modules_unload(1);
    ERR_free_strings();
    EVP_cleanup();
    sk_SSL_COMP_free(SSL_COMP_get_compression_methods());
    CRYPTO_cleanup_all_ex_data();
}

int
ssl_ctx_init(DTLSParams* k, const char* keyname)
{
    int result = 0;

    // Create a new context using DTLS
    k->ctx = SSL_CTX_new(DTLSv1_method());
    if (k->ctx == NULL) {
        printf("Error: cannot create SSL_CTX.\n");
        ERR_print_errors_fp(stderr);
        return -1;
    }

    // Set our supported ciphers
    result = SSL_CTX_set_cipher_list(k->ctx, "ALL:!ADH:!LOW:!EXP:!MD5:@STRENGTH");
    if (result != 1) {
        printf("Error: cannot set the cipher list.\n");
        ERR_print_errors_fp(stderr);
        return -2;
    }

    // The client doesn't have to send it's certificate
    SSL_CTX_set_verify(k->ctx, SSL_VERIFY_PEER, ssl_verify_peer);

    // // Enable srtp
    // result = SSL_CTX_set_tlsext_use_srtp(k->ctx, "SRTP_AES128_CM_SHA1_80");
    // if (result != 0) {
    //     printf("Error: cannot setup srtp.\n");
    //     ERR_print_errors_fp(stderr);
    //     return -3;
    // }

    // Load key and certificate
    char certfile[1024];
    char keyfile[1024];
    sprintf(certfile, "./%s-cert.pem", keyname);
    sprintf(keyfile, "./%s-key.pem", keyname);

    // certificate file; contains also the public key
    result = SSL_CTX_use_certificate_file(k->ctx, certfile, SSL_FILETYPE_PEM);
    if (result != 1) {
        printf("Error: cannot load certificate file.\n");
        ERR_print_errors_fp(stderr);
        return -4;
    }

    // Load private key
    result = SSL_CTX_use_PrivateKey_file(k->ctx, keyfile, SSL_FILETYPE_PEM);
    if (result != 1) {
        printf("Error: cannot load private key file.\n");
        ERR_print_errors_fp(stderr);
        return -5;
    }

    // Check if the private key is valid
    result = SSL_CTX_check_private_key(k->ctx);
    if (result != 1) {
        printf("Error: checking the private key failed. \n");
        ERR_print_errors_fp(stderr);
        return -6;
    }

    return 0;
}

int ssl_verify_peer(int ok, X509_STORE_CTX* ctx) {
    return 1;
}

int
ssl_init(DTLSParams* k, int isserver, info_callback cb)
{
    if (isserver == 0) { // if client
        k->bio = BIO_new_ssl_connect(k->ctx);
        if (k->bio == NULL) {
            fprintf(stderr, "error connecting to server\n");
        }

        BIO_set_conn_hostname(k->bio, "127.0.0.1:4433");
        BIO_get_ssl(k->bio, &(k->ssl));
        if (k->ssl == NULL) {
            fprintf(stderr, "error, exit\n");
            exit(-1);
        }

        SSL_set_connect_state(k->ssl);
        SSL_set_mode(k->ssl, SSL_MODE_AUTO_RETRY);
        SSL_set_tlsext_host_name(k->ssl, "127.0.0.1");
    } else {
        k->bio = BIO_new_ssl_connect(k->ctx);
        if (k->bio == NULL) {
            fprintf(stderr, "error connecting with BIOs\n");
        }

        BIO_get_ssl(k->bio, &(k->ssl));
        if (k->ssl == NULL) {
            fprintf(stderr, "error, exit\n");
            exit(-1);
        }

        SSL_set_accept_state(k->ssl);
    }

    return 0;
}

void
ssl_info_callback(const SSL* ssl, int where, int ret, const char* name)
{
    if (ret == 0) {
        printf("-- krx_ssl_info_callback: error occured.\n");
        return;
      }

      SSL_WHERE_INFO(ssl, where, SSL_CB_LOOP, "LOOP");
      SSL_WHERE_INFO(ssl, where, SSL_CB_HANDSHAKE_START, "HANDSHAKE START");
      SSL_WHERE_INFO(ssl, where, SSL_CB_HANDSHAKE_DONE, "HANDSHAKE DONE");
}

void
ssl_shutdown(DTLSParams* k)
{
    if (k == NULL) {
        return;
    }

    if (k->ctx != NULL) {
        SSL_CTX_free(k->ctx);
        k->ctx = NULL;
    }

    if (k->ssl != NULL) {
        SSL_free(k->ssl);
        k->ssl = NULL;
    }
}
