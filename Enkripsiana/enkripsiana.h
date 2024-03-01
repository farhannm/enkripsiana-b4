#pragma once
#ifndef ENKRIPSIANA_H
#define ENKRIPSIANA_H

#include <stdio.h>
#include <stdint.h>
#include <string.h>

#define AES_256_KEY_LENGTH 32
#define AES_BLOCK_SIZE 192

void keyExpansion(const uint8_t* key, uint8_t* roundKeys);
void addRoundKey(uint8_t* state, const uint8_t* roundKey);
void subBytes(uint8_t* state);
void shiftRows(uint8_t* state);
uint8_t galoisMult(uint8_t a, uint8_t b);
void mixColumns(uint8_t* state);
void aes256EncryptBlock(const uint8_t* input, const uint8_t* roundKeys, uint8_t* output);
size_t readFile(const char* filename, uint8_t* buffer, size_t bufferSize);
void writeFile(const char* filename, const uint8_t* buffer, size_t dataSize);
void readPrivateKey(uint8_t* key, size_t keyLength);

//call in main
int encryptFile();

#endif 
