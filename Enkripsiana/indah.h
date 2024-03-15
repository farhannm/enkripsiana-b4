#pragma once
#ifndef INDAH_H
#define INDAH_H

#include <stdio.h>
#include <stdint.h>
#include <string.h>

// Modul untuk melakukan operasi AddRoundkey sebanyak 10 kali putaran
void addRoundKey(aes_state_t* state, const aes_key_t* key)

// Modul untuk melakukan enkripsi dari penggabungan setiap modul 
void aes128EncryptBlock(&state, &key);

#endif // !INDAH_H
