#pragma once

#include <nat20/crypto.h>


struct CryptoImplBSSL {
    static n20_crypto_error_t open(n20_crypto_context_t** ctx);
    static n20_crypto_error_t close(n20_crypto_context_t* ctx);
};
