#ifndef dtls_h_
#define dtls_h_

#include <openssl/err.h>
#include <openssl/dh.h>
#include <openssl/ssl.h>
#include <openssl/conf.h>
#include <openssl/engine.h>

typedef struct {
  SSL_CTX* ctx;
  SSL* ssl;
  BIO *bio;
} DTLSParams;

typedef void(*info_callback)();

void dtls_begin();

void dtls_end();

void ssl_shutdown(DTLSParams* k);

void ssl_info_callback(const SSL* ssl, int where, int ret, const char* name);

int ssl_ctx_init(DTLSParams* k, const char* keyname);

int ssl_verify_peer(int ok, X509_STORE_CTX* ctx);

int ssl_init(DTLSParams* k, int isserver, info_callback cb);

#endif // dtls_h_
