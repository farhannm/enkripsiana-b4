#pragma once
#ifndef INDAH_H
#define INDAH_H

#include <stdio.h>
#include <stdint.h>
#include <string.h>

#define AES_128_KEY_LENGTH 16
#define AES_128_STATE_LENGTH 16
#define AES_BLOCK_SIZE 128
#define NR 10

//Define AES state and key
typedef struct {
	uint8_t state[AES_128_STATE_LENGTH];
} aes_state_t;

typedef struct {
	uint8_t key[AES_128_KEY_LENGTH];
} aes_key_t;

// Modul untuk melakukan operasi AddRoundkey sebanyak 10 kali putaran
void addRoundKey(aes_state_t* state, const aes_key_t* key);

// Modul untuk melakukan enkripsi dari penggabungan setiap modul 
void aes128EncryptBlock(aes_state_t *state, const aes_key_t *key);

#endif // !INDAH_H
