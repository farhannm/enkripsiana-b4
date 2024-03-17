#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include "dirent.h"
#include "enkripsiana.h"

//sBox
unsigned char sBox[256] = {
        0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
        0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0,
        0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
        0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75,
        0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84,
        0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
        0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8,
        0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2,
        0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
        0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB,
        0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79,
        0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
        0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A,
        0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E,
        0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
        0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16
};

//Rcon
unsigned char Rcon[10] = {
    0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36
};

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
void addRoundKey(aes_state_t* state, const aes_key_t* key) {
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


// Fungsi Galois Multiply dalam Galois Field
uint8_t gmul(uint8_t a, uint8_t b) {
    // gmul merupakan nama fungsi dengan parameter uint8_t a, uint8_t b, 
    // a dan b adalah parameter input yang masing masing mewakili satu byte kunci encrypt 

    uint8_t p = 0;          // membuat variabel p bertipe uint8_t yang nantinya akan terlibat dalam proses XOR
    uint8_t temp;           // membuat variabel temp bertipe uint8_t sebagai penampung bit
    int i = 0;              // membuat variabel i bertipe integer untuk perulangan dan di assign 0 

    for (i < 8; i++;) {     // Jika i bernilai kurang dari 8 maka akan melakukan proses, dan setiap kali perulangan terjadi i bertambah 1
        if (b & 1) {        // operasi bitwise antara "b" dan 1 untuk mengecek bit paling tidak signifikan bernilai 1 atau tidak
            p ^= a;         // variabel p di XOR kan dengan a
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
<<<<<<< Updated upstream
void aes128EncryptBlock(aes_state_t* state, const aes_key_t* key) {
    for (int round = 1; round < NR; round++) {
=======
void aes128EncryptBlock(uint8_t* state, uint8_t* key) {
    for (int round = 1; round < 10; ++round) {
>>>>>>> Stashed changes
        subBytes(state);
        shiftRows(state->state);
        mixColumns(state->state);
        addRoundKey(state, &key[round]);
    }
<<<<<<< Updated upstream

    // Final round
=======
>>>>>>> Stashed changes
    subBytes(state);
    shiftRows(state->state);
    addRoundKey(state, &key[NR]);
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
    aes_state_t state;
    aes_key_t keyStruct;

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

<<<<<<< Updated upstream
=======
    readPrivateKey(key, keyLength);

    uint8_t inputData[AES_BLOCK_SIZE];
    size_t bytesRead = readFile(fullInputPath, inputData, sizeof(inputData));
    if (bytesRead == 0) {
        return 1;
    }

    // Mendapatkan nama direktori dari path input
    char outputDirectory[256];
    strncpy(outputDirectory, inputDirectory, sizeof(outputDirectory));

    // Membuat nama file output sesuai dengan input pengguna
    char outputFileName[256];
    snprintf(outputFileName, sizeof(outputFileName), "%s/encrypted_%s", outputDirectory, inputFileName);

    // Enkripsi file
    void aes128EncryptBlock(uint8_t* state, uint8_t* key);

    // Mengubah isi file menjadi chiper text
    writeFile(outputFileName, state.state, sizeof(state.state));

    // Hapus file asli
    remove(fullInputPath);

    printf("[SUCCESS] File berhasil dienkripsi. Enkripsi tersimpan di '%s'\n", outputFileName);

>>>>>>> Stashed changes
    return 0;
}

