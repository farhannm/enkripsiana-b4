#pragma once
#pragma warning(disable : 4996)
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include "dirent.h"
#include "enkripsiana.h"
#include "farhan.h"
#include "febi.h"
#include "hasbi.h"
#include "indah.h"
#include "farel.h"

void keyExpansionCore(uint8_t* in, unsigned char i) {
    //Rotate Left:
    unsigned int* q = (unsigned int*)in;
    *q = (*q >> 8) | ((*q & 0xff) << 24);

    // S-Box 4 bytes:
    in[0] = sBox[in[0]]; 
    in[1] = sBox[in[1]];
    in[2] = sBox[in[2]]; 
    in[3] = sBox[in[3]];

    //Rcon
    in[0] ^= Rcon[i];
}

void keyExpansion(uint8_t* inputKey, uint8_t* expandedKeys) {
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
void addRoundKey(uint8_t *state, uint8_t *key) {
    for (int i = 0; i < AES_128_STATE_LENGTH; i++) {
        state[i] ^= key[i];
    }
}

// SubBytes operation
void subBytes(uint8_t* state) {
    for (int i = 0; i < AES_128_STATE_LENGTH; i++) {
        state[i] = sBox[state[i]];
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

// Fungsi Galois Multiply dalam Galois Field
uint8_t gmul(uint8_t a, uint8_t b) {
    // gmul merupakan nama fungsi dengan parameter uint8_t a, uint8_t b, 
    // a dan b adalah parameter input yang masing masing mewakili satu byte kunci encrypt 

    uint8_t p = 0;  // membuat variabel p bertipe uint8_t yang nantinya akan terlibat dalam proses XOR
    uint8_t temp;   // membuat variabel temp bertipe uint8_t sebagai penampung bit
    int i = 0;      // membuat variabel i bertipe integer untuk perulangan dan di assign 0 

    for (i < 8; i++;) {// Jika i bernilai kurang dari 8 maka akan melakukan proses, dan setiap kali perulangan terjadi i bertambah 1
        if (b & 1) { // operasi bitwise antara "b" dan 1 untuk mengecek bit paling tidak signifikan bernilai 1 atau tidak
            p ^= a; // variabel p di XOR kan dengan a
        }

        temp = a & 0x80;    // operasi bitwise antara a dengan 0x80 sebagai bit paling signifikan
                            // 0x80 adalah nilai konstanta heksa yang mewakili nilai 128

        a <<= 1;            // menggeser setiap bit dalam "a" ke kiri
                            // misal 000110 menjadi 001100

        if (temp) {         // mengecek apakah nilai temp true atau tidak
            a ^= 0x1B;      // operasi XOR "a" dengan 0x1B untuk mengecek apakah operasi perkalian dilakukan dengan benar
                            // 0x1B digunakan karena sesuai dengan polinomial ireduksi
        }

        b >>= 1;            // menggeser setiap bit dalam "b" ke kanan
    }

    return p;               // mengembalikan nilai p
}

// MixColumns operation
void mixColumns(uint8_t* state) {
    uint8_t temp[4][4];

    for (int i = 0; i < 4; i++) {
        temp[0][i] = gmul(0x02, state[0 + i]) ^ gmul(0x03, state[4 + i]) ^ state[8 + i] ^ state[12 + i];
        temp[1][i] = state[0 + i] ^ gmul(0x02, state[4 + i]) ^ gmul(0x03, state[8 + i]) ^ state[12 + i];
        temp[2][i] = state[0 + i] ^ state[4 + i] ^ gmul(0x02, state[8 + i]) ^ gmul(0x03, state[12 + i]);
        temp[3][i] = gmul(0x03, state[0 + i]) ^ state[4 + i] ^ state[8 + i] ^ gmul(0x02, state[12 + i]);
    }

    // Return the mixed result to the original state
    for (int r = 0; r < 4; r++) {
        for (int i = 0; i < 4; i++) {
            state[r * 4 + i] = temp[r][i];
        }
    }
}

// AES-128 encryption algorithm
void aes128EncryptBlock(uint8_t* input, uint8_t* key, uint8_t* output) {
    uint8_t state[AES_BLOCK_SIZE];
    memcpy(state, input, AES_BLOCK_SIZE);


    for (int round = 1; round < 10; ++round) {
        subBytes(state);
        shiftRows(state);
        mixColumns(state);
        addRoundKey(state, &key[round]);
    }

    subBytes(state);
    shiftRows(state);
    addRoundKey(state, &key[NR]);

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
    printf("Daftar file yang tersedia untuk dienkripsi:\n");
    while ((entry = readdir(dir)) != NULL) {
        if (entry->d_type == DT_REG) {
            printf("%d. %s\n", ++fileCount, entry->d_name);
        }
    }

    closedir(dir);

    // Jika tidak ada file dalam direktori "Crypto", berikan pesan dan keluar
    if (fileCount == 0) {
        printf("[INFO] Tidak ada file yang ditemukan dalam direktori 'Crypto'.\n");
        return 1;
    }

    // Meminta pengguna untuk memasukkan nomor indeks file
    int fileIndex;
    do {
        printf("\n[INPUT] Masukkan nomor indeks file yang akan dienkripsi : ");
        if (scanf("%d", &fileIndex) != 1) {
            printf("[ERROR] Masukkan nomor indeks yang valid.\n");
            while (getchar() != '\n'); // Membersihkan input buffer
        }
        else if (fileIndex < 1 || fileIndex > fileCount) {
            printf("[ERROR] Nomor indeks tidak valid.\n");
        }
        else {
            break; // Keluar dari loop jika nomor indeks valid
        }
    } while (1);

    // Mencari nama file yang sesuai dengan nomor indeks
    dir = opendir(inputDirectory);
    int currentIndex = 0;
    char inputFileName[256];
    while ((entry = readdir(dir)) != NULL) {
        if (entry->d_type == DT_REG) {
            currentIndex++;
            if (currentIndex == fileIndex) {
                strcpy(inputFileName, entry->d_name);
                break;
            }
        }
    }
    closedir(dir);

    char fullInputPath[512];
    snprintf(fullInputPath, sizeof(fullInputPath), "%s/%s", inputDirectory, inputFileName);

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

    backOrExit();

    return 0;
}

int decryptFile() {
    printf("\n[WARNING] Belum diimplementasikan.\n");

    backOrExit();

    return 0;
}

void backOrExit() {
    int opsi, encrypt;
    bool isValid;

    do {
        printf("\n[INFO]Proses selesai\n\n");
        printf("(1). Kembali ke menu utama \n");
        printf("(2). Keluar dari aplikasi \n");
        printf("\n[>>] Masukkan pilihan (1/2) : ");
        scanf("%d", &opsi);

        switch (opsi) {
        case 1:
            system("cls");
            
            mainMenu();
            isValid = true;
            break;
        case 2:
            printf("\nKeluar dari aplikasi...\n");
            exit(0);
            break;
        default:
            printf("\nInput tidak valid. Masukkan angka antara 1 hingga 3.\n");
            isValid = false;
            break;

        }

    } while (!isValid);
}

void mainMenu() {
    int opsi, encrypt, decrypt;
    bool isValid;

    printf("+-------------------------------+\n");
    printf("|     E N K R I P S I A N A     |\n");
    printf("+-------------------------------+\n");

    do {
        printf("\nPilih aksi yang akan dilakukan : \n");
        printf("(1). Enkripsi \n");
        printf("(2). Deskripsi\n");
        printf("(3). Keluar dari aplikasi \n");
        printf("\n[>>] Masukkan pilihan (1-3) : ");
        scanf("%d", &opsi);

        switch (opsi) {
        case 1:
            system("cls");
            printf("+----------------------------------+\n");
            printf("|              Enkripsi            |\n");
            printf("+----------------------------------+\n\n");

            encrypt = encryptFile();
            isValid = true;
            break;
        case 2:
            system("cls");
            printf("+--------------------------------+\n");
            printf("|            Deskripsi           |\n");
            printf("+--------------------------------+\n");

            decrypt = decryptFile();
            isValid = true;
            break;
        case 3:
            printf("\nKeluar dari aplikasi...\n");
            exit(0);
            break;
        default:
            printf("\nInput tidak valid. Masukkan angka antara 1 hingga 3.\n");
            isValid = false;
            break;

        }

    } while (!isValid);
}

