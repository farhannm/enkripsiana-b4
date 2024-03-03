
#pragma once
#pragma warning(disable : 4996)
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include "dirent.h"
#include "enkripsiana.h"

void keyExpansion(const uint8_t* key, uint8_t* roundKeys) {
    uint32_t* w = (uint32_t*)roundKeys;

    memcpy(w, key, AES_128_KEY_LENGTH);

    for (int i = 4; i < 44; ++i) {
        uint32_t temp = w[i - 1];
        if (i % 4 == 0) {
            temp = ((temp << 8) & 0xFFFFFF00) | ((temp >> 24) & 0x000000FF);
            temp = sBox[temp >> 24] | (sBox[(temp >> 16) & 0xFF] << 8) | (sBox[(temp >> 8) & 0xFF] << 16) | (sBox[temp & 0xFF] << 24);
            temp ^= (rCon[i / 4] << 24);
        }
        w[i] = w[i - 4] ^ temp;
    }
}


// AddRoundKey operation
void addRoundKey(uint8_t* state, const uint8_t* roundKey) {
    for (int i = 0; i < AES_BLOCK_SIZE; ++i) {
        state[i] ^= roundKey[i];
    }
}

// SubBytes operation
void subBytes(uint8_t* state) {
  
    for (int i = 0; i < AES_BLOCK_SIZE; ++i) {
        state[i] = sBox[state[i]];
    }
}

// ShiftRows operation
void shiftRows(uint8_t* state) {
    // Shift row 1
    uint8_t temp = state[1];
    state[1] = state[5];
    state[5] = state[9];
    state[9] = state[13];
    state[13] = temp;

    // Shift row 2
    temp = state[2];
    state[2] = state[10];
    state[10] = temp;
    temp = state[6];
    state[6] = state[14];
    state[14] = temp;

    // Shift row 3
    temp = state[3];
    state[3] = state[15];
    state[15] = state[11];
    state[11] = state[7];
    state[7] = temp;
}

// Galois Multiplication
uint8_t galoisMult(uint8_t a, uint8_t b) {
    uint8_t result = 0;
    uint8_t hiBitSet;

    for (int i = 0; i < 8; ++i) {
        if ((b & 1) == 1) {
            result ^= a;
        }

        hiBitSet = (a & 0x80) != 0;
        a <<= 1;

        if (hiBitSet) {
            a ^= 0x1B;
        }

        b >>= 1;
    }

    return result;
}

// MixColumns operation
void mixColumns(uint8_t* state) {


    for (int i = 0; i < 4; ++i) {
        uint8_t s0 = state[i];
        uint8_t s1 = state[i + 4];
        uint8_t s2 = state[i + 8];
        uint8_t s3 = state[i + 12];

        state[i] = galoisMult(0x02, s0) ^ galoisMult(0x03, s1) ^ s2 ^ s3;
        state[i + 4] = s0 ^ galoisMult(0x02, s1) ^ galoisMult(0x03, s2) ^ s3;
        state[i + 8] = s0 ^ s1 ^ galoisMult(0x02, s2) ^ galoisMult(0x03, s3);
        state[i + 12] = galoisMult(0x03, s0) ^ s1 ^ s2 ^ galoisMult(0x02, s3);
    }
}

// AES-128 encryption algorithm
void aes128EncryptBlock(const uint8_t* input, const uint8_t* roundKeys, uint8_t* output) {
    uint8_t state[AES_BLOCK_SIZE];
    memcpy(state, input, AES_BLOCK_SIZE);

    addRoundKey(state, roundKeys);

    for (int round = 1; round < 10; ++round) {
        subBytes(state);
        shiftRows(state);
        mixColumns(state);
        addRoundKey(state, roundKeys + (round * AES_BLOCK_SIZE));
    }

    subBytes(state);
    shiftRows(state);
    addRoundKey(state, roundKeys + 10 * AES_BLOCK_SIZE);

    memcpy(output, state, AES_BLOCK_SIZE);
}

size_t readFile(const char* filename, uint8_t* buffer, size_t bufferSize) {
    FILE* file = fopen(filename, "rb");
    if (!file) {
        perror("[!] Gagal membuka file.");
        return 0;
    }

    size_t bytesRead = fread(buffer, 1, bufferSize, file);
    fclose(file);
    return bytesRead;
}

// Function to write the contents of a buffer to a file
void writeFile(const char* filename, const uint8_t* buffer, size_t dataSize) {
    FILE* file = fopen(filename, "wb");
    if (!file) {
        perror("[!] Gagal membuka file.");
        return;
    }

    fwrite(buffer, 1, dataSize, file);
    fclose(file);
}

int fileExists(const char* filename) {
    FILE* file = fopen(filename, "r");
    if (file) {
        fclose(file);
        return 1;
    }
    return 0;
}

void readPrivateKey(uint8_t* key, size_t keyLength) {
    char inputKey[17]; // 16 karakter + 1 untuk null terminator
    while (1) {
        printf("[INPUT] Masukkan kunci (perlu 16 karakter): ");
        scanf("%16s", inputKey);
        if (strlen(inputKey) == 16) {
            break; // Keluar dari loop jika panjang kunci sesuai
        }
        else {
            printf("\n[WARNING] Kunci harus memiliki panjang 16 karakter.\n");
            // Membersihkan input buffer
            int c;
            while ((c = getchar()) != '\n' && c != EOF) {}
        }
    }
    // Salin kunci ke dalam buffer keluaran
    memcpy(key, inputKey, 16);
}


void listFilesInDirectory(const char* directory) {
    DIR* dir;
    struct dirent* ent;
    int fileCount = 0;
    char fileList[100][256]; // Array untuk menyimpan nama file (maksimum 100 file, masing-masing dengan panjang nama file maksimum 256 karakter)

    if ((dir = opendir(directory)) != NULL) {
        printf("[INFO] Daftar file di direktori : \n", directory);
        while ((ent = readdir(dir)) != NULL) {
            if (ent->d_type == DT_REG) { // Hanya proses file reguler
                strcpy(fileList[fileCount], ent->d_name); // Menyalin nama file ke dalam array fileList
                fileCount++;
            }
        }
        closedir(dir);

        // Menampilkan daftar file beserta nomor urutannya
        for (int i = 0; i < fileCount; i++) {
            printf("%d. %s\n", i + 1, fileList[i]);
        }
    }
    else {
        perror("[!] Gagal membuka direktori.");
    }
}


int encryptFile() {
    const char* inputDirectory = "Crypto"; // Current directory
    const size_t keyLength = AES_128_KEY_LENGTH;
    uint8_t key[AES_128_KEY_LENGTH];

    // Memeriksa apakah direktori "Crypto" memiliki file
    DIR* dir = opendir(inputDirectory);
    if (!dir) {
        printf("[ERROR] Direktori 'Crypto' tidak ditemukan atau tidak dapat diakses.\n");
        return 1;
    }

    struct dirent* entry;
    int fileCount = 0;

    // Menghitung jumlah file dalam direktori "Crypto"
    while ((entry = readdir(dir)) != NULL) {
        if (entry->d_type == DT_REG) {
            fileCount++;
        }
    }

    closedir(dir);

    // Jika tidak ada file dalam direktori "Crypto", berikan pesan dan keluar
    if (fileCount == 0) {
        printf("[INFO] Tidak ada file yang ditemukan dalam direktori 'Crypto'.\n");
        return 1;
    }

    listFilesInDirectory(inputDirectory);

    char inputFileName[256];
    printf("\n[INPUT] Masukkan nama file yang akan dienkripsi : ");
    scanf("%s", inputFileName);

    char fullInputPath[512];
    snprintf(fullInputPath, sizeof(fullInputPath), "%s/%s", inputDirectory, inputFileName);

    while (!fileExists(fullInputPath)) {
        system("cls");
        printf("[ERROR] File '%s' tidak ada di dalam direktori.\n\n", inputFileName);

        listFilesInDirectory(inputDirectory);

        printf("\n[INPUT] Masukkan nama file yang akan dienkripsi : ");
        scanf("%s", inputFileName);
        snprintf(fullInputPath, sizeof(fullInputPath), "%s/%s", inputDirectory, inputFileName);
    }

    readPrivateKey(key, keyLength);

    uint8_t inputData[AES_BLOCK_SIZE];
    size_t bytesRead = readFile(fullInputPath, inputData, sizeof(inputData));
    if (bytesRead == 0) {
        return 1;
    }

    uint8_t roundKeys[11 * AES_BLOCK_SIZE];
    keyExpansion(key, roundKeys);

    // Mendapatkan nama direktori dari path input
    char outputDirectory[256];
    strncpy(outputDirectory, inputDirectory, sizeof(outputDirectory));

    // Membuat nama file output sesuai dengan input pengguna
    char outputFileName[256];
    snprintf(outputFileName, sizeof(outputFileName), "%s/encrypted_%s", outputDirectory, inputFileName);

    uint8_t encryptedOutput[AES_BLOCK_SIZE];
    aes128EncryptBlock(inputData, roundKeys, encryptedOutput);

    writeFile(outputFileName, encryptedOutput, sizeof(encryptedOutput));

    // Hapus file asli
    remove(fullInputPath);

    printf("[SUCCESS] File berhasil dienkripsi. Enkripsi tersimpan di '%s'\n", outputFileName);

    return 0;
}

