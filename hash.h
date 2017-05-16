/*
 * hash.h
 *
 *  Created on: Apr 23, 2017
 *      Author: cossete
 */

#ifndef HASH_H_
#define HASH_H_

#include <openssl/sha.h>
#include <openssl/ripemd.h>

void sha256(uint8_t *digest, const uint8_t *message, size_t len) {
    SHA256_CTX ctx;
    SHA256_Init(&ctx);
    SHA256_Update(&ctx, message, len);
    SHA256_Final(digest, &ctx);
}

void rmd160(uint8_t *digest, const uint8_t *message, size_t len) {
    RIPEMD160_CTX ctx;
    RIPEMD160_Init(&ctx);
    RIPEMD160_Update(&ctx, message, len);
    RIPEMD160_Final(digest, &ctx);
}

void hash256(uint8_t *digest, const uint8_t *message, size_t len) {
    uint8_t tmp[SHA256_DIGEST_LENGTH];
    sha256(tmp, message, len);
    sha256(digest, tmp, SHA256_DIGEST_LENGTH);
}

void hash160(uint8_t *digest, const uint8_t *message, size_t len) {
    uint8_t tmp[SHA256_DIGEST_LENGTH];
    sha256(tmp, message, len);
    rmd160(digest, tmp, SHA256_DIGEST_LENGTH);
}

#endif /* HASH_H_ */
