#include <stdint.h>
#include <stdio.h>
#include "enkripsiana.h"

/**
 * https://en.wikipedia.org/wiki/Finite_field_arithmetic
 * Multiply two numbers in the GF(2^8) finite field defined
 * by the polynomial x^8 + x^4 + x^3 + x + 1 = 0
 * We do use mul2(int8_t a) but not mul(uint8_t a, uint8_t b)
 * just in order to get a higher speed.
 */
static inline uint8_t mul2(uint8_t a) {
    return (a & 0x80) ? ((a << 1) ^ 0x1b) : (a << 1);
}

/**
 * @purpose:    ShiftRows
 * @descrption:
 *  Row0: s0  s4  s8  s12   <<< 0 byte
 *  Row1: s1  s5  s9  s13   <<< 1 byte
 *  Row2: s2  s6  s10 s14   <<< 2 bytes
 *  Row3: s3  s7  s11 s15   <<< 3 bytes
 */
static void shift_rows(uint8_t* state) {
    uint8_t temp;
    // row1
    temp = *(state + 1);
    *(state + 1) = *(state + 5);
    *(state + 5) = *(state + 9);
    *(state + 9) = *(state + 13);
    *(state + 13) = temp;
    // row2
    temp = *(state + 2);
    *(state + 2) = *(state + 10);
    *(state + 10) = temp;
    temp = *(state + 6);
    *(state + 6) = *(state + 14);
    *(state + 14) = temp;
    // row3
    temp = *(state + 15);
    *(state + 15) = *(state + 11);
    *(state + 11) = *(state + 7);
    *(state + 7) = *(state + 3);
    *(state + 3) = temp;
}

/**
 * @purpose:    Inverse ShiftRows
 * @description
 *  Row0: s0  s4  s8  s12   >>> 0 byte
 *  Row1: s1  s5  s9  s13   >>> 1 byte
 *  Row2: s2  s6  s10 s14   >>> 2 bytes
 *  Row3: s3  s7  s11 s15   >>> 3 bytes
 */
static void inv_shift_rows(uint8_t* state) {
    uint8_t temp;
    // row1
    temp = *(state + 13);
    *(state + 13) = *(state + 9);
    *(state + 9) = *(state + 5);
    *(state + 5) = *(state + 1);
    *(state + 1) = temp;
    // row2
    temp = *(state + 14);
    *(state + 14) = *(state + 6);
    *(state + 6) = temp;
    temp = *(state + 10);
    *(state + 10) = *(state + 2);
    *(state + 2) = temp;
    // row3
    temp = *(state + 3);
    *(state + 3) = *(state + 7);
    *(state + 7) = *(state + 11);
    *(state + 11) = *(state + 15);
    *(state + 15) = temp;
}

void aes_key_schedule_128(const uint8_t* key, uint8_t* roundkeys) {

    uint8_t temp[4];
    uint8_t* last4bytes; // point to the last 4 bytes of one round
    uint8_t* lastround;
    uint8_t i;

    for (i = 0; i < 16; ++i) {
        *roundkeys++ = *key++;
    }

    last4bytes = roundkeys - 4;
    for (i = 0; i < AES_ROUNDS; ++i) {
        // k0-k3 for next round
        temp[3] = SBOX[*last4bytes++];
        temp[0] = SBOX[*last4bytes++];
        temp[1] = SBOX[*last4bytes++];
        temp[2] = SBOX[*last4bytes++];
        temp[0] ^= RC[i];
        lastround = roundkeys - 16;
        *roundkeys++ = temp[0] ^ *lastround++;
        *roundkeys++ = temp[1] ^ *lastround++;
        *roundkeys++ = temp[2] ^ *lastround++;
        *roundkeys++ = temp[3] ^ *lastround++;
        // k4-k7 for next round        
        *roundkeys++ = *last4bytes++ ^ *lastround++;
        *roundkeys++ = *last4bytes++ ^ *lastround++;
        *roundkeys++ = *last4bytes++ ^ *lastround++;
        *roundkeys++ = *last4bytes++ ^ *lastround++;
        // k8-k11 for next round
        *roundkeys++ = *last4bytes++ ^ *lastround++;
        *roundkeys++ = *last4bytes++ ^ *lastround++;
        *roundkeys++ = *last4bytes++ ^ *lastround++;
        *roundkeys++ = *last4bytes++ ^ *lastround++;
        // k12-k15 for next round
        *roundkeys++ = *last4bytes++ ^ *lastround++;
        *roundkeys++ = *last4bytes++ ^ *lastround++;
        *roundkeys++ = *last4bytes++ ^ *lastround++;
        *roundkeys++ = *last4bytes++ ^ *lastround++;
    }
}

void aes_encrypt_128(const uint8_t* roundkeys, const uint8_t* plaintext, uint8_t* ciphertext) {

    uint8_t tmp[16], t;
    uint8_t i, j;

    // first AddRoundKey
    for (i = 0; i < AES_BLOCK_SIZE; ++i) {
        *(ciphertext + i) = *(plaintext + i) ^ *roundkeys++;
    }

    // 9 rounds
    for (j = 1; j < AES_ROUNDS; ++j) {

        // SubBytes
        for (i = 0; i < AES_BLOCK_SIZE; ++i) {
            *(tmp + i) = SBOX[*(ciphertext + i)];
        }
        shift_rows(tmp);
        /*
         * MixColumns
         * [02 03 01 01]   [s0  s4  s8  s12]
         * [01 02 03 01] . [s1  s5  s9  s13]
         * [01 01 02 03]   [s2  s6  s10 s14]
         * [03 01 01 02]   [s3  s7  s11 s15]
         */
        for (i = 0; i < AES_BLOCK_SIZE; i += 4) {
            t = tmp[i] ^ tmp[i + 1] ^ tmp[i + 2] ^ tmp[i + 3];
            ciphertext[i] = mul2(tmp[i] ^ tmp[i + 1]) ^ tmp[i] ^ t;
            ciphertext[i + 1] = mul2(tmp[i + 1] ^ tmp[i + 2]) ^ tmp[i + 1] ^ t;
            ciphertext[i + 2] = mul2(tmp[i + 2] ^ tmp[i + 3]) ^ tmp[i + 2] ^ t;
            ciphertext[i + 3] = mul2(tmp[i + 3] ^ tmp[i]) ^ tmp[i + 3] ^ t;
        }

        // AddRoundKey
        for (i = 0; i < AES_BLOCK_SIZE; ++i) {
            *(ciphertext + i) ^= *roundkeys++;
        }

    }

    // last round
    for (i = 0; i < AES_BLOCK_SIZE; ++i) {
        *(ciphertext + i) = SBOX[*(ciphertext + i)];
    }
    shift_rows(ciphertext);
    for (i = 0; i < AES_BLOCK_SIZE; ++i) {
        *(ciphertext + i) ^= *roundkeys++;
    }

}

void aes_decrypt_128(const uint8_t* roundkeys, const uint8_t* ciphertext, uint8_t* plaintext) {

    uint8_t tmp[16];
    uint8_t t, u, v;
    uint8_t i, j;

    roundkeys += 160;

    // first round
    for (i = 0; i < AES_BLOCK_SIZE; ++i) {
        *(plaintext + i) = *(ciphertext + i) ^ *(roundkeys + i);
    }
    roundkeys -= 16;
    inv_shift_rows(plaintext);
    for (i = 0; i < AES_BLOCK_SIZE; ++i) {
        *(plaintext + i) = INV_SBOX[*(plaintext + i)];
    }

    for (j = 1; j < AES_ROUNDS; ++j) {

        // Inverse AddRoundKey
        for (i = 0; i < AES_BLOCK_SIZE; ++i) {
            *(tmp + i) = *(plaintext + i) ^ *(roundkeys + i);
        }

        /*
         * Inverse MixColumns
         * [0e 0b 0d 09]   [s0  s4  s8  s12]
         * [09 0e 0b 0d] . [s1  s5  s9  s13]
         * [0d 09 0e 0b]   [s2  s6  s10 s14]
         * [0b 0d 09 0e]   [s3  s7  s11 s15]
         */
        for (i = 0; i < AES_BLOCK_SIZE; i += 4) {
            t = tmp[i] ^ tmp[i + 1] ^ tmp[i + 2] ^ tmp[i + 3];
            plaintext[i] = t ^ tmp[i] ^ mul2(tmp[i] ^ tmp[i + 1]);
            plaintext[i + 1] = t ^ tmp[i + 1] ^ mul2(tmp[i + 1] ^ tmp[i + 2]);
            plaintext[i + 2] = t ^ tmp[i + 2] ^ mul2(tmp[i + 2] ^ tmp[i + 3]);
            plaintext[i + 3] = t ^ tmp[i + 3] ^ mul2(tmp[i + 3] ^ tmp[i]);
            u = mul2(mul2(tmp[i] ^ tmp[i + 2]));
            v = mul2(mul2(tmp[i + 1] ^ tmp[i + 3]));
            t = mul2(u ^ v);
            plaintext[i] ^= t ^ u;
            plaintext[i + 1] ^= t ^ v;
            plaintext[i + 2] ^= t ^ u;
            plaintext[i + 3] ^= t ^ v;
        }

        // Inverse ShiftRows
        inv_shift_rows(plaintext);

        // Inverse SubBytes
        for (i = 0; i < AES_BLOCK_SIZE; ++i) {
            *(plaintext + i) = INV_SBOX[*(plaintext + i)];
        }

        roundkeys -= 16;

    }

    // last AddRoundKey
    for (i = 0; i < AES_BLOCK_SIZE; ++i) {
        *(plaintext + i) ^= *(roundkeys + i);
    }

}

void impEncrypt() {

}

void impDecrypt() {

}