#ifndef ENKRIPSIANA_H
#define ENKRIPSIANA_H

#include <stdio.h>
#include <stdint.h>
#include <string.h>

#define AES_128_KEY_LENGTH 16
#define AES_128_STATE_LENGTH 16
#define AES_BLOCK_SIZE 128
#define NR 10

// Define AES state and key
typedef struct {
    uint8_t state[AES_128_STATE_LENGTH];
} aes_state_t;

typedef struct {
    uint8_t key[AES_128_KEY_LENGTH];
} aes_key_t;

// Declare sBox array
extern unsigned char sBox[256];

// Declare Rcon array
extern unsigned char Rcon[10];

// Declare AES functions
void keyExpansion();
void addRoundKey(aes_state_t* state, const aes_key_t* key);
void subBytes(aes_state_t* state);
void shiftRows(uint8_t* state);
void mixColumns(aes_state_t* state);
void aes128EncryptBlock(aes_state_t* state, const aes_key_t* key);
void readPrivateKey();
int encryptFile();

// File operations
size_t readFile(const char* filename, uint8_t* buffer, size_t bufferSize);
void writeFile(const char* filename, const uint8_t* buffer, size_t dataSize);
void listFilesInDirectory(const char* directory);
int fileExists(const char* filename);

#endif