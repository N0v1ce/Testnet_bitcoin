/*
 * varint.h
 *
 *  Created on: Apr 24, 2017
 *      Author: cossete
 */

#ifndef VARINT_H_
#define VARINT_H_

#include <stdint.h>
#include "endian.h"

typedef enum {
    VARINT16 = 0xfd,
    VARINT32 = 0xfe,
    VARINT64 = 0xff
} varint_t;

uint64_t varint_get(uint8_t *bytes, size_t *len) {
    uint8_t prefix = *bytes;
    uint64_t value;

    *len = sizeof(uint8_t); /*total length of varint including prefix and number of var real length*/
                            /*call by reference, for example, varint is 3 bytes*/
    if (prefix < VARINT16) {
        value = prefix;
    } else {
        uint8_t *ptr = bytes + *len;

        switch (prefix) {
            case VARINT16:
                value = eint16(LITTLE, *(uint16_t *)ptr);
                *len += sizeof(uint16_t);
                break;
            case VARINT32:
                value = eint32(LITTLE, *(uint32_t *)ptr);
                *len += sizeof(uint32_t);
                break;
            case VARINT64:
                value = eint64(LITTLE, *(uint64_t *)ptr);
                *len += sizeof(uint64_t);
                break;
        }
    }

    return value;
}

void varint_set(uint8_t *bytes, uint64_t n, size_t *len) {  /*given length then to create varint */
    *len = sizeof(uint8_t);  /*total length of varint including prefix and real length*/

    if (n < VARINT16) {
        *bytes = (uint8_t)n;
    } else {
        uint8_t header;

        if (n <= UINT16_MAX) {
            header = VARINT16;
            *(uint16_t *)(bytes + 1) = eint16(LITTLE, n);
            *len += sizeof(uint16_t);
        } else if (n <= UINT32_MAX) {
            header = VARINT32;
            *(uint32_t *)(bytes + 1) = eint32(LITTLE, n);
            *len += sizeof(uint32_t);
        } else {
            header = VARINT64;
            *(uint64_t *)(bytes + 1) = eint64(LITTLE, n);
            *len += sizeof(uint64_t);
        }

        *bytes = header;
    }
}

size_t varint_size(uint64_t n) {
    if (n < VARINT16) {
        return 1;
    } else if (n <= UINT16_MAX) {
        return 1 + sizeof(uint16_t);
    } else if (n <= UINT32_MAX) {
        return 1 + sizeof(uint32_t);
    } else {
        return 1 + sizeof(uint64_t);
    }
}

#endif /* VARINT_H_ */
