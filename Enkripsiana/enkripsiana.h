#pragma once
#ifndef ENKRIPSIANA_H
#define ENKRIPSIANA_H

typedef unsigned char byte; // Tipe data untuk merepresentasikan byte (8-bit)

// Struktur data untuk menyimpan state enkripsi
typedef struct {
    byte data[4][4]; // Matriks 4x4 untuk menyimpan byte-byte state
} State;

// Struktur data untuk menyimpan kunci ekspansi
typedef struct {
    byte data[11][16]; // Array 2 dimensi untuk menyimpan kunci ekspansi
} ExpandedKey;

// Fungsi untuk mengenkripsi file teks
void encryptFile(const char* inputFile, const char* outputFile, const char* key);

// Fungsi untuk ekspansi kunci utama
void expandMainKey(const char* key, ExpandedKey* expandedKey);

// Fungsi untuk pencampuran subkunci
void mixSubKey(ExpandedKey* expandedKey);

// Fungsi untuk transformasi: ByteSub, ShiftRow, dan MixColumn
void transform(State* state);

// Fungsi untuk pencampuran subkunci dengan XOR
void mixSubKeyXOR(ExpandedKey* expandedKey, int round);

#endif 
