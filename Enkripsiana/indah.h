#pragma once
#ifndef INDAH_H
#define INDAH_H

#include <stdint.h>
#include "enkripsiana.h"

// Modul untuk melakukan operasi AddRoundkey sebanyak 10 kali putaran
void addRoundKey(uint8_t* state, uint8_t* key);

// Modul untuk melakukan enkripsi dari penggabungan setiap modul 
void aes128EncryptBlock(uint8_t* input, uint8_t* key, uint8_t* output);

#endif // !INDAH_H
