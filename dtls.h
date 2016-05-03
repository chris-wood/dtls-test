#ifndef dtls_h_
#define dtls_h_

#include <stdbool.h>

#include <openssl/err.h>
#include <openssl/dh.h>
#include <openssl/ssl.h>
#include <openssl/conf.h>
#include <openssl/engine.h>

typedef struct {
    SSL_CTX *ctx;
    SSL *ssl;
    BIO *bio;
} DTLSParams;

void dtls_Begin();
void dtls_End();
void dtls_Shutdown(DTLSParams* k);
int dtls_InitContextFromKeystore(DTLSParams* k, const char* keyname);
int dtls_InitServer(DTLSParams* k);
int dtls_InitClient(DTLSParams* k, const char *address);

#endif // dtls_h_
