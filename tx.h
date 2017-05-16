/*
 * tx.h
 *
 *  Created on: Apr 25, 2017
 *      Author: cossete
 */

#ifndef TX_H_
#define TX_H_

#include <stdint.h>
#include "common.h"
#include "endian.h"
#include "varint.h"

typedef struct {
    uint64_t value;
    uint64_t script_len;
    uint8_t *script;
} txout_t;

typedef struct {
    uint8_t txid[32];
    uint32_t index;
} outpoint_t;

typedef struct {
    outpoint_t outpoint;
    uint64_t script_len;
    uint8_t *script;
    uint32_t sequence;
} txin_t;

typedef struct {
    uint32_t version;
    uint64_t inputs_len;
    txin_t *inputs;
    uint64_t outputs_len;
    txout_t *outputs;
    uint32_t locktime;
} tx_t;

typedef enum {
    SIGHASH_ALL = 0x01
} sighash_t;

typedef uint8_t *message_t;


/*this a C routine that create outpoint from unspent output */
/*outpoint will then be put into input*/
void outpoint_fill(outpoint_t *outpoint, const char *txid, uint32_t index) {
    parse_hex(outpoint->txid, txid);
    reverse(outpoint->txid, 32);
    outpoint->index = eint32(LITTLE, index);
}

/*this is a C routine that create an output(txout_t) given value needed to transfer
 * and p2pkh address receiving the money*/
/*an output contains an output script and the value of bitcoins*/
void txout_create_p2pkh(txout_t *txout, const uint64_t value, const char *hash160) {
    char script[52] = { 0 };
    sprintf(script, "76a914%s88ac", hash160);/*OP_DUP, OP_HASH160, OP_EQUALVERIFY, OP_CHECKSIG*/

    txout->value = eint64(LITTLE, value);
    txout->script = alloc_hex(script, (size_t *)&txout->script_len);/*change char into uint8_t*/
}

void txout_destroy(txout_t *txout) {
    free(txout->script);
}


/*this is a C routine that create an input(txin_t) given outpoint, signature and public key*/
void txin_create_p2pkh(txin_t *txin, const outpoint_t *outpoint,
        const char *sig, const char *pub, sighash_t flag) {

    char script[400] = { 0 };
    sprintf(script, "%02lx%s%02x%02lx%s", strlen(sig) / 2 + 1, sig, flag, strlen(pub) / 2, pub);

    memcpy(&txin->outpoint, outpoint, sizeof(outpoint_t));
    txin->script = alloc_hex(script, (size_t *)&txin->script_len);
    txin->sequence = 0xffffffff;
}

void txin_destroy(txin_t *txin) {
    free(txin->script);
}

/* signable message */
/*create a fake input for our message by copy the corresponding UTXO script*/
void txin_create_signable(txin_t *txin, const outpoint_t *outpoint, const txout_t *utxo) {
    memcpy(&txin->outpoint, outpoint, sizeof(outpoint_t));
    txin->script_len = utxo->script_len;
    txin->script = malloc(utxo->script_len);
    memcpy(txin->script, utxo->script, utxo->script_len);
    txin->sequence = 0xffffffff;
}


/*used in modified tx, we only keep the related input in the tx for the input signature*/
void txin_create_truncated(txin_t *txin, const outpoint_t *outpoint) {
    memcpy(&txin->outpoint, outpoint, sizeof(outpoint_t));
    txin->script_len = 0;
    txin->script = NULL;
    txin->sequence = 0xffffffff;
}

/*during serialization of tx, need to know the length of tx in advance*/
size_t tx_size(const tx_t *tx, sighash_t flag) {
    size_t size = 0;
    int i;

    /* version */
    size += sizeof(uint32_t);

    /* inputs count */
    size += varint_size(tx->inputs_len);

    /* inputs */
    for (i = 0; i < tx->inputs_len; ++i) {
        txin_t *txin = &tx->inputs[i];

        /* outpoint */
        size += sizeof(outpoint_t);

        /* script */
        size += varint_size(txin->script_len);
        size += txin->script_len;

        /* sequence */
        size += sizeof(uint32_t);
    }

    /* outputs count */
    size += varint_size(tx->outputs_len);

    /* outputs */
    for (i = 0; i < tx->outputs_len; ++i) {
        txout_t *txout = &tx->outputs[i];

        /* value */
        size += sizeof(uint64_t);

        /* script */
        size += varint_size(txout->script_len);
        size += txout->script_len;
    }

    /* locktime */
    size += sizeof(uint32_t);

    if (flag) {

        /* sighash */
        size += sizeof(uint32_t);
    }

    return size;
}

void tx_serialize(const tx_t *tx, uint8_t *raw, sighash_t flag) {
    uint8_t *ptr;
    size_t varlen;
    int i;

    ptr = raw;

    /* version */
    *(uint32_t *)ptr = eint32(LITTLE, tx->version);
    ptr += sizeof(uint32_t);

    /* inputs count */
    varint_set(ptr, tx->inputs_len, &varlen);
    ptr += varlen;

    /* inputs */
    for (i = 0; i < tx->inputs_len; ++i) {
        txin_t *txin = &tx->inputs[i];

        /* outpoint */
        memcpy(ptr, txin->outpoint.txid, 32);
        ptr += 32;
        *(uint32_t *)ptr = eint32(LITTLE, txin->outpoint.index);
        ptr += sizeof(uint32_t);

        /* script */
        varint_set(ptr, txin->script_len, &varlen);
        ptr += varlen;
        memcpy(ptr, txin->script, txin->script_len);
        ptr += txin->script_len;

        /* sequence */
        *(uint32_t *)ptr = eint32(LITTLE, txin->sequence);
        ptr += sizeof(uint32_t);
    }

    /* outputs count */
    varint_set(ptr, tx->outputs_len, &varlen);
    ptr += varlen;

    /* outputs */
    for (i = 0; i < tx->outputs_len; ++i) {
        txout_t *txout = &tx->outputs[i];

        /* value */
        *(uint64_t *)ptr = eint64(LITTLE, txout->value);
        ptr += sizeof(uint64_t);

        /* script */
        varint_set(ptr, txout->script_len, &varlen);
        ptr += varlen;
        memcpy(ptr, txout->script, txout->script_len);
        ptr += txout->script_len;
    }

    /* locktime */
    *(uint32_t *)ptr = eint32(LITTLE, tx->locktime);
    ptr += sizeof(uint32_t);

    if (flag) {

        /* sighash */
        *(uint32_t *)ptr = eint32(LITTLE, flag);
    }
}

#endif /* TX_H_ */
