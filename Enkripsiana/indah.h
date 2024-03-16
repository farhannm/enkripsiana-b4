#pragma once
#ifndef INDAH_H
#define INDAH_H

#include <stdint.h>
#include "enkripsiana.h"

// Modul untuk melakukan operasi AddRoundkey sebanyak 10 kali putaran
void addRoundKey(aes_state_t* state, aes_key_t* key);

// Modul untuk melakukan enkripsi dari penggabungan setiap modul 
void aes128EncryptBlock(aes_state_t *state, aes_key_t *key);

#endif // !INDAH_H
