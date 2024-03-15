#pragma once
#pragma warning(disable : 4996)
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include "dirent.h"
#include "enkripsiana.h"

void keyExpansionCore(unsigned char* in, unsigned char i) {
//Rotate Left:
    unsigned int* q = (unsigned int*)in;
    *q = (*q >> 8) | ((*q & 0xff) << 24);

// S-Box 4 bytes:
    in[0] = sBox[in[0]]; in[1] = sBox[in[1]];
    in[2] = sBox[in[2]]; in[3] = sBox[in[3]];

//Rcon
    in[0] ^= Rcon[i];
}

void keyExpansion(unsigned char* inputKey, unsigned char* expandedKeys) {
    //16 Original key:
    for (int i = 0; i < 16; i++)
        expandedKeys[i] = inputKey[i];

    //Variables:
    int bytesGenerated = 16;
    int RconIteration = 1;
    unsigned char temp[4];

    while (bytesGenerated < 176) {
        //Read 4 bytes for the core:
        for (int i = 0; i < 4; i++)
            temp[i] = expandedKeys[i + bytesGenerated - 4];

        //Perform the core once for each 16 byte key:
        if (bytesGenerated % 16 == 0) {
            keyExpansionCore(temp, RconIteration);
            RconIteration++;
        }

        //XOR temp with [bytesGenerates-16], and store in expandedKeys:
        for (unsigned char a = 0; a < 4; a++) {
            expandedKeys[bytesGenerated] =
                expandedKeys[bytesGenerated - 16] ^ temp[a];
            bytesGenerated++;
        }
    }
}


// AddRoundKey operation
void addRoundKey(aes_state_t *state, const aes_key_t *key) {
    for (int i = 0; i < AES_128_STATE_LENGTH; i++) {
        state->state[i] ^= key->key[i];
    }
}

// SubBytes operation
void subBytes(aes_state_t* state) {
    for (int i = 0; i < AES_128_STATE_LENGTH; i++) {
        state->state[i] = sBox[state->state[i]];
    }
}

// ShiftRows operation
void shiftRows(uint8_t* state) {
    uint8_t temp[4][4]; // Matriks sementara untuk menyimpan hasil pergeseran

    // Proses ShiftRows
    for (int r = 0; r < 4; r++) {
        for (int c = 0; c < 4; c++) {
            if (r == 0) { // Jika ini adalah baris pertama, tidak ada pergeseran
                temp[r][c] = state[r * 4 + c];
            }
            else { 
                temp[r][c] = state[r * 4 + (c + r) % 4]; // Pergeseran baris
            }
        }
    }

    // Mengembalikan hasil pergeseran ke state asli
    for (int r = 0; r < 4; r++) {
        for (int c = 0; c < 4; c++) {
            state[r * 4 + c] = temp[r][c];
        }
    }
}


// MixColumns operation
void mixColumns(aes_state_t* state) {
    uint8_t(*sBox)(uint8_t) {};
    int i, j;
    i = 0;
    j = 0;
    uint8_t temp[i][j];

    for (i < 4; ++i;) {
        for (j < 4; ++j;) {
            temp[i][j] = state->state[j];
            temp[i][j] = state->state[j + 4];
            temp[i][j] = state->state[j + 8];
            temp[i][j] = state->state[j + 12];

            state->state[j] = sBox(temp[0] ^ temp[3]) ^ temp[1];
            state->state[j + 4] = sBox(temp[0] ^ temp[3]) ^ temp[1];
            state->state[j + 8] = sBox(temp[0] ^ temp[3]) ^ temp[1];
            state->state[j + 12] = sBox(temp[0] ^ temp[3]) ^ temp[1];
        }
        temp[0] = state->state[i];
        temp[1] = state->state[i + 4];
        temp[2] = state->state[i + 8];
        temp[3] = state->state[i + 12];

        state->state[i] = sBox(temp[0] ^ temp[3]) ^ temp[1];
        state->state[i + 4] = sBox(temp[0] ^ temp[3]) ^ temp[1];
        state->state[i + 8] = sBox(temp[0] ^ temp[3]) ^ temp[1];
        state->state[i + 12] = sBox(temp[0] ^ temp[3]) ^ temp[1];
    }
}

// AES-128 encryption algorithm
void aes128EncryptBlock() {
    
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

void readPrivateKey() {

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

    return 0;
}

