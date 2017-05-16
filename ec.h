/*
 * ec.h
 *
 *  Created on: Apr 24, 2017
 *      Author: cossete
 */

#ifndef EC_H_
#define EC_H_

#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/obj_mac.h>
#include <openssl/ecdsa.h>

/*use this function to create ec key pair with the help of OpenSSL*/
EC_KEY *ec_new_keypair(const uint8_t *priv_bytes) {
    EC_KEY *key;                    /*EC_KEY is a data structure OpenSSL defines, holding ec key pair*/
    BIGNUM *priv;                   /*BIGNUM and BN_CTX are data structure holding big number during intermediate step*/
    BN_CTX *ctx;
    const EC_GROUP *group;          /*data structure holding generator group*/
    EC_POINT *pub;                  /*holding the product of group and private key which is public key*/

    /* init empty OpenSSL EC keypair */

    key = EC_KEY_new_by_curve_name(NID_secp256k1);

    /* set private key through BIGNUM */

    priv = BN_new();
    BN_bin2bn(priv_bytes, 32, priv);
    EC_KEY_set_private_key(key, priv);

    /* derive public key from private key and group */

    ctx = BN_CTX_new();
    BN_CTX_start(ctx);

    group = EC_KEY_get0_group(key);
    pub = EC_POINT_new(group);
    EC_POINT_mul(group, pub, priv, NULL, NULL, ctx);
    EC_KEY_set_public_key(key, pub);

    /* release resources */

    EC_POINT_free(pub);
    BN_CTX_end(ctx);
    BN_CTX_free(ctx);
    BN_clear_free(priv);

    return key;
}

EC_KEY *ec_new_pubkey(const uint8_t *pub_bytes, size_t pub_len) {
    EC_KEY *key;
    const uint8_t *pub_bytes_copy;

    key = EC_KEY_new_by_curve_name(NID_secp256k1);
    pub_bytes_copy = pub_bytes;
    o2i_ECPublicKey(&key, &pub_bytes_copy, pub_len);

    return key;
}

#endif /* EC_H_ */
