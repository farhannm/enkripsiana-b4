#pragma warning(disable : 4996)
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <ctime>
#include "enkripsiana.h"
#include "dirent.h"
#include "uihead.h"

/**
 * https://en.wikipedia.org/wiki/Finite_field_arithmetic
 * Multiply two numbers in the GF(2^8) finite field defined
 * by the polynomial x^8 + x^4 + x^3 + x + 1 = 0
 * We do use mul2(int8_t a) but not mul(uint8_t a, uint8_t b)
 * just in order to get a higher speed.
 */
static inline uint8_t mul2(uint8_t a) {
    return (a & 0x80) ? ((a << 1) ^ 0x1b) : (a << 1);
}

/**
 * @purpose:    ShiftRows
 * @descrption:
 *  Row0: s0  s4  s8  s12   <<< 0 byte
 *  Row1: s1  s5  s9  s13   <<< 1 byte
 *  Row2: s2  s6  s10 s14   <<< 2 bytes
 *  Row3: s3  s7  s11 s15   <<< 3 bytes
 */
static void shift_rows(uint8_t* state) {
    uint8_t temp;
    // row1
    temp = *(state + 1);
    *(state + 1) = *(state + 5);
    *(state + 5) = *(state + 9);
    *(state + 9) = *(state + 13);
    *(state + 13) = temp;
    // row2
    temp = *(state + 2);
    *(state + 2) = *(state + 10);
    *(state + 10) = temp;
    temp = *(state + 6);
    *(state + 6) = *(state + 14);
    *(state + 14) = temp;
    // row3
    temp = *(state + 15);
    *(state + 15) = *(state + 11);
    *(state + 11) = *(state + 7);
    *(state + 7) = *(state + 3);
    *(state + 3) = temp;
}

/**
 * @purpose:    Inverse ShiftRows
 * @description
 *  Row0: s0  s4  s8  s12   >>> 0 byte
 *  Row1: s1  s5  s9  s13   >>> 1 byte
 *  Row2: s2  s6  s10 s14   >>> 2 bytes
 *  Row3: s3  s7  s11 s15   >>> 3 bytes
 */
static void inv_shift_rows(uint8_t* state) {
    uint8_t temp;
    // row1
    temp = *(state + 13);
    *(state + 13) = *(state + 9);
    *(state + 9) = *(state + 5);
    *(state + 5) = *(state + 1);
    *(state + 1) = temp;
    // row2
    temp = *(state + 14);
    *(state + 14) = *(state + 6);
    *(state + 6) = temp;
    temp = *(state + 10);
    *(state + 10) = *(state + 2);
    *(state + 2) = temp;
    // row3
    temp = *(state + 3);
    *(state + 3) = *(state + 7);
    *(state + 7) = *(state + 11);
    *(state + 11) = *(state + 15);
    *(state + 15) = temp;
}

void aes_key_schedule_128(const uint8_t* key, uint8_t* roundkeys) {

    uint8_t temp[4];
    uint8_t* last4bytes; // point to the last 4 bytes of one round
    uint8_t* lastround;
    uint8_t i;

    for (i = 0; i < 16; ++i) {
        *roundkeys++ = *key++;
    }

    last4bytes = roundkeys - 4;
    for (i = 0; i < AES_ROUNDS; ++i) {
        // k0-k3 for next round
        temp[3] = SBOX[*last4bytes++];
        temp[0] = SBOX[*last4bytes++];
        temp[1] = SBOX[*last4bytes++];
        temp[2] = SBOX[*last4bytes++];
        temp[0] ^= RC[i];
        lastround = roundkeys - 16;
        *roundkeys++ = temp[0] ^ *lastround++;
        *roundkeys++ = temp[1] ^ *lastround++;
        *roundkeys++ = temp[2] ^ *lastround++;
        *roundkeys++ = temp[3] ^ *lastround++;
        // k4-k7 for next round        
        *roundkeys++ = *last4bytes++ ^ *lastround++;
        *roundkeys++ = *last4bytes++ ^ *lastround++;
        *roundkeys++ = *last4bytes++ ^ *lastround++;
        *roundkeys++ = *last4bytes++ ^ *lastround++;
        // k8-k11 for next round
        *roundkeys++ = *last4bytes++ ^ *lastround++;
        *roundkeys++ = *last4bytes++ ^ *lastround++;
        *roundkeys++ = *last4bytes++ ^ *lastround++;
        *roundkeys++ = *last4bytes++ ^ *lastround++;
        // k12-k15 for next round
        *roundkeys++ = *last4bytes++ ^ *lastround++;
        *roundkeys++ = *last4bytes++ ^ *lastround++;
        *roundkeys++ = *last4bytes++ ^ *lastround++;
        *roundkeys++ = *last4bytes++ ^ *lastround++;
    }
}

void aes_encrypt_128(const uint8_t* roundkeys, const uint8_t* plaintext, uint8_t* ciphertext) {

    uint8_t tmp[16], t;
    uint8_t i, j;

    // first AddRoundKey
    for (i = 0; i < AES_BLOCK_SIZE; ++i) {
        *(ciphertext + i) = *(plaintext + i) ^ *roundkeys++;
    }

    // 9 rounds
    for (j = 1; j < AES_ROUNDS; ++j) {

        // SubBytes
        for (i = 0; i < AES_BLOCK_SIZE; ++i) {
            *(tmp + i) = SBOX[*(ciphertext + i)];
        }
        shift_rows(tmp);
        /*
         * MixColumns
         * [02 03 01 01]   [s0  s4  s8  s12]
         * [01 02 03 01] . [s1  s5  s9  s13]
         * [01 01 02 03]   [s2  s6  s10 s14]
         * [03 01 01 02]   [s3  s7  s11 s15]
         */
        for (i = 0; i < AES_BLOCK_SIZE; i += 4) {
            t = tmp[i] ^ tmp[i + 1] ^ tmp[i + 2] ^ tmp[i + 3];
            ciphertext[i] = mul2(tmp[i] ^ tmp[i + 1]) ^ tmp[i] ^ t;
            ciphertext[i + 1] = mul2(tmp[i + 1] ^ tmp[i + 2]) ^ tmp[i + 1] ^ t;
            ciphertext[i + 2] = mul2(tmp[i + 2] ^ tmp[i + 3]) ^ tmp[i + 2] ^ t;
            ciphertext[i + 3] = mul2(tmp[i + 3] ^ tmp[i]) ^ tmp[i + 3] ^ t;
        }

        // AddRoundKey
        for (i = 0; i < AES_BLOCK_SIZE; ++i) {
            *(ciphertext + i) ^= *roundkeys++;
        }

    }

    // last round
    for (i = 0; i < AES_BLOCK_SIZE; ++i) {
        *(ciphertext + i) = SBOX[*(ciphertext + i)];
    }
    shift_rows(ciphertext);
    for (i = 0; i < AES_BLOCK_SIZE; ++i) {
        *(ciphertext + i) ^= *roundkeys++;
    }

}

void aes_decrypt_128(const uint8_t* roundkeys, const uint8_t* ciphertext, uint8_t* plaintext) {

    uint8_t tmp[16];
    uint8_t t, u, v;
    uint8_t i, j;

    roundkeys += 160;

    // first round
    for (i = 0; i < AES_BLOCK_SIZE; ++i) {
        *(plaintext + i) = *(ciphertext + i) ^ *(roundkeys + i);
    }
    roundkeys -= 16;
    inv_shift_rows(plaintext);
    for (i = 0; i < AES_BLOCK_SIZE; ++i) {
        *(plaintext + i) = INV_SBOX[*(plaintext + i)];
    }

    for (j = 1; j < AES_ROUNDS; ++j) {

        // Inverse AddRoundKey
        for (i = 0; i < AES_BLOCK_SIZE; ++i) {
            *(tmp + i) = *(plaintext + i) ^ *(roundkeys + i);
        }

        /*
         * Inverse MixColumns
         * [0e 0b 0d 09]   [s0  s4  s8  s12]
         * [09 0e 0b 0d] . [s1  s5  s9  s13]
         * [0d 09 0e 0b]   [s2  s6  s10 s14]
         * [0b 0d 09 0e]   [s3  s7  s11 s15]
         */
        for (i = 0; i < AES_BLOCK_SIZE; i += 4) {
            t = tmp[i] ^ tmp[i + 1] ^ tmp[i + 2] ^ tmp[i + 3];
            plaintext[i] = t ^ tmp[i] ^ mul2(tmp[i] ^ tmp[i + 1]);
            plaintext[i + 1] = t ^ tmp[i + 1] ^ mul2(tmp[i + 1] ^ tmp[i + 2]);
            plaintext[i + 2] = t ^ tmp[i + 2] ^ mul2(tmp[i + 2] ^ tmp[i + 3]);
            plaintext[i + 3] = t ^ tmp[i + 3] ^ mul2(tmp[i + 3] ^ tmp[i]);
            u = mul2(mul2(tmp[i] ^ tmp[i + 2]));
            v = mul2(mul2(tmp[i + 1] ^ tmp[i + 3]));
            t = mul2(u ^ v);
            plaintext[i] ^= t ^ u;
            plaintext[i + 1] ^= t ^ v;
            plaintext[i + 2] ^= t ^ u;
            plaintext[i + 3] ^= t ^ v;
        }

        // Inverse ShiftRows
        inv_shift_rows(plaintext);

        // Inverse SubBytes
        for (i = 0; i < AES_BLOCK_SIZE; ++i) {
            *(plaintext + i) = INV_SBOX[*(plaintext + i)];
        }

        roundkeys -= 16;

    }

    // last AddRoundKey
    for (i = 0; i < AES_BLOCK_SIZE; ++i) {
        *(plaintext + i) ^= *(roundkeys + i);
    }

}

char* readFile(const char* fileName) {
    FILE* file = fopen(fileName, "r");
    if (!file) {
        printf("[ERROR] Gagal membuka file '%s' untuk dibaca.\n", fileName);
        return NULL;
    }

    fseek(file, 0, SEEK_END);
    long fileSize = ftell(file);
    fseek(file, 0, SEEK_SET);

    char* buffer = (char*)malloc(fileSize + 1);
    if (!buffer) {
        printf("[ERROR] Gagal mengalokasikan memori untuk file '%s'.\n", fileName);
        fclose(file);
        return NULL;
    }

    size_t elementsRead = fread(buffer, fileSize, 1, file);
    fclose(file);

    if (elementsRead != 1) {
        printf("[ERROR] Gagal membaca file '%s'.\n", fileName);
        free(buffer);
        return NULL;
    }

    buffer[fileSize] = '\0';
    return buffer;
}

int readFileDataByte(const char* filename, uint8_t* buffer, size_t buffer_size) {
    FILE* file = fopen(filename, "rb"); // Buka file dalam mode binary read

    if (!file) {
        printf("[ERROR] Gagal membuka file '%s' untuk dibaca.\n", filename);
        return 0; // Gagal membuka file
    }

    // Membaca data dari file ke dalam buffer
    size_t bytes_read = fread(buffer, 1, buffer_size, file);

    fclose(file); // Tutup file

    // Periksa apakah jumlah byte yang dibaca sesuai dengan buffer_size
    if (bytes_read != buffer_size) {
        printf("[ERROR] Gagal membaca data dari file '%s'.\n", filename);
        return 0; // Gagal membaca data dari file
    }

    return 1; // Berhasil membaca data dari file
}

// Function to write the contents of a buffer to a file
int writeFile(const char* fileName, const void* data, size_t dataSize) {
    FILE* file = fopen(fileName, "w");
    if (!file) {
        printf("[ERROR] Gagal membuka file '%s' untuk ditulis.\n", fileName);
        return 0;
    }

    size_t elementsWritten = fwrite(data, dataSize, 1, file);
    fclose(file);

    if (elementsWritten != 1) {
        printf("[ERROR] Gagal menulis ke file '%s'.\n", fileName);
        return 0;
    }

    return 1;
}

// Fungsi untuk menulis data ke dalam file
int writeFileByte(const char* filename, uint8_t* data, size_t data_size) {
    FILE* file = fopen(filename, "wb"); // Buka file dalam mode binary write

    if (!file) {
        printf("[ERROR] Gagal membuka file '%s' untuk ditulis.\n", filename);
        return 0; // Gagal membuka file
    }

    // Menulis data ke dalam file
    size_t bytes_written = fwrite(data, 1, data_size, file);

    fclose(file); // Tutup file

    // Periksa apakah jumlah byte yang ditulis sesuai dengan data_size
    if (bytes_written != data_size) {
        printf("[ERROR] Gagal menulis data ke dalam file '%s'.\n", filename);
        return 0; // Gagal menulis data ke dalam file
    }

    return 1; // Berhasil menulis data ke dalam file
}

int writeListToFile(const char* fileName, Node* head) {
    FILE* file = fopen(fileName, "w");
    if (!file) {
        printf("[ERROR] Gagal membuka file '%s' untuk ditulis.\n", fileName);
        return 0;
    }

    Node* current = head;
    do {
        fwrite(&(current->data), sizeof(char), 1, file);
        current = current->next;
    } while (current != head);

    fclose(file);
    return 1;
}


int fileExists(const char* filename) {
    FILE* file = fopen(filename, "r");
    if (file) {
        fclose(file);
        return 1;
    }
    return 0;
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

char* padPlainText(const char* plain_text) {
    // Padding jika panjang plaintext kurang dari 16 karakter
    int padding_len = AES_BLOCK_SIZE - strlen(plain_text);
    char* padded_text = (char*)malloc(AES_BLOCK_SIZE + 1); // 1 extra for null-terminator
    if (!padded_text) {
        printf("[ERROR] Memory allocation failed.\n");
        return NULL;
    }
    strcpy(padded_text, plain_text);
    for (int i = 0; i < padding_len; ++i) {
        strcat(padded_text, " ");
    }
    return padded_text;
}

int impEncrypt() {
    const char* inputDirectory = "Plain"; // Input Dir
    const char* outputDirectory = "Encrypted"; // Output Dir
    char key[17]; // 16 karakter untuk kunci AES dan 1 karakter untuk null-terminator

    uint8_t roundkeys[AES_ROUND_KEY_SIZE]; // Key schedule

    uint8_t ciphertext[AES_BLOCK_SIZE]; // Output

    DIR* dir = opendir(inputDirectory);
    if (!dir) {
        printf("[ERROR] Direktori tidak ditemukan atau tidak dapat diakses.\n");
        return 1;
    }

    struct dirent* entry;
    int fileCount = 0;

    // Menghitung jumlah file dalam direktori "Plain"
    while ((entry = readdir(dir)) != NULL) {
        if (entry->d_type == DT_REG) {
            fileCount++;
        }
    }

    // Jika tidak ada file dalam direktori "Plain", berikan pesan dan keluar
    if (fileCount == 0) {
        printf("[INFO] Tidak ada file yang ditemukan dalam direktori.\n");
        closedir(dir);
        backOrExit();
    }

    // Meminta pengguna untuk memilih file yang akan dienkripsi
    printf("Daftar file yang tersedia untuk dienkripsi:\n");
    rewinddir(dir); // Reset directory pointer
    int currentFileIndex = 0;
    while ((entry = readdir(dir)) != NULL) {
        if (entry->d_type == DT_REG) {
            printf("%d. %s\n", ++currentFileIndex, entry->d_name);
        }
    }
    closedir(dir);

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

    // Baca plain text dari file yang dipilih
    char* plain_text = readFile(fullInputPath);
    if (!plain_text) {
        printf("[ERROR] Gagal membaca plain text dari file '%s'.\n", fullInputPath);
        return 1;
    }

    // Padding plain text
    char* padded_text = padPlainText(plain_text);
    if (!padded_text) {
        free(plain_text);
        return 1;
    }

    // Input key
while (1) {
    printf("[INPUT] Masukkan kunci (perlu 16 karakter): ");
    scanf("%16s", key); // Membaca input dari pengguna, maksimal 16 karakter

    // Menghapus newline character jika ada di buffer
    int c;
    while ((c = getchar()) != '\n' && c != EOF);

    // Memeriksa panjang kunci
    if (strlen(key) == 16) { // Panjang harus 16 karakter
        break; // Keluar dari loop jika panjang kunci sesuai
    }
    else {
        // Jika input lebih panjang atau lebih pendek dari yang diharapkan, tampilkan pesan peringatan
        printf("\n[WARNING] Kunci harus memiliki panjang 16 karakter\n\n");
    }
}
    aes_key_schedule_128((uint8_t*)key, roundkeys);

    // Encryption
    aes_encrypt_128(roundkeys, (uint8_t*)padded_text, ciphertext);

    // Output cipher text sebelum pengacakan
    printf("\nCipher text sebelum pengacakan:\n");
    for (int i = 0; i < AES_BLOCK_SIZE; i++) {
        printf("%c ", ciphertext[i]);
    }
    printf("\n");

    // Simpan hasil enkripsi ke dalam linked list
    Node* head = NULL;
    for (int i = 0; i < AES_BLOCK_SIZE; i++) {
        insertEnd(&head, ciphertext[i]);
    }

    // Shuffle linked list
    shuffleNode(&head);

    // Output cipher text setelah pengacakan
    printf("\nCipher text setelah pengacakan :\n");
    printList(head);

    // Menyisipkan karakter diantara setiap karakter yang dienkripsi
    insertAfterEachNode(&head, '.');

    // Output cipher text setelah penyisipan
    printf("\nCipher text setelah penyisipan :\n");
    printList(head);

    // Simpan linked list (hasil pengacakan) ke dalam file
    char outputFileName[512];
    snprintf(outputFileName, sizeof(outputFileName), "%s/encrypted_%s", outputDirectory, inputFileName);
    if (!writeListToFile(outputFileName, head)) {
        printf("[ERROR] Gagal menyimpan hasil pengacakan ke dalam file '%s'.\n", outputFileName);
        free(plain_text);
        free(padded_text);
        return 1;
    }

    remove(fullInputPath);

    printf("[SUCCESS] File berhasil dienkripsi. Enkripsi tersimpan di '%s'\n", outputFileName);

    free(plain_text);
    free(padded_text);

    backOrExit();

    return 0;
}



int impDecrypt() {
    const char* inputDirectory = "Encrypted"; // Input Dir
    const char* outputDirectory = "Decrypted"; // Output Dir
    char key[17]; // 16 karakter untuk kunci AES dan 1 karakter untuk null-terminator

    uint8_t roundkeys[AES_ROUND_KEY_SIZE]; // Key schedule

    // Memeriksa apakah direktori "Encrypted" memiliki file
    DIR* dir = opendir(inputDirectory);
    if (!dir) {
        printf("[ERROR] Direktori tidak ditemukan atau tidak dapat diakses.\n");
        return 1;
    }

    struct dirent* entry;
    int fileCount = 0;

    // Menghitung jumlah file dalam direktori "Encrypted"
    while ((entry = readdir(dir)) != NULL) {
        if (entry->d_type == DT_REG) {
            fileCount++;
        }
    }

    // Jika tidak ada file dalam direktori "Encrypted", berikan pesan dan keluar
    if (fileCount == 0) {
        printf("\n[INFO] Tidak ada file yang ditemukan dalam direktori.\n");
        closedir(dir);
        backOrExit();
    }
    else {
        // Menghitung jumlah file dalam direktori "Encrypted"
        printf("Daftar file yang tersedia untuk didekripsi:\n");
        rewinddir(dir); // Reset directory pointer
        int currentFileIndex = 0;
        while ((entry = readdir(dir)) != NULL) {
            if (entry->d_type == DT_REG) {
                printf("%d. %s\n", ++currentFileIndex, entry->d_name);
            }
        }

        closedir(dir);
    }

    // Meminta pengguna untuk memasukkan nomor indeks file
    int fileIndex;
    do {
        printf("\n[INPUT] Masukkan nomor indeks file yang akan didekripsi : ");
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

    // Baca ciphertext dari file yang dipilih
    uint8_t ciphertext[32];
    FILE* inputFile = fopen(fullInputPath, "rb");
    if (!inputFile) {
        printf("[ERROR] Gagal membaca ciphertext dari file '%s'.\n", fullInputPath);
        return 1;
    }
    fread(ciphertext, 1, 32, inputFile);
    fclose(inputFile);

    // Input key
while (1) {
    printf("[INPUT] Masukkan kunci (perlu 16 karakter): ");
    scanf("%16s", key); // Membaca input dari pengguna, maksimal 16 karakter

    // Menghapus newline character jika ada di buffer
    int c;
    while ((c = getchar()) != '\n' && c != EOF);

    // Memeriksa panjang kunci
    if (strlen(key) == 16) { // Panjang harus 16 karakter
        break; // Keluar dari loop jika panjang kunci sesuai
    }
    else {
        // Jika input lebih panjang atau lebih pendek dari yang diharapkan, tampilkan pesan peringatan
        printf("\n[WARNING] Kunci harus memiliki panjang 16 karakter\n\n");
    }
}
    aes_key_schedule_128((uint8_t*)key, roundkeys);

    // Simpan ciphertext ke dalam linked list
    Node* head = NULL;
    for (int i = 0; i < 32; i++) {
        insertEnd(&head, ciphertext[i]);
    }

    // Output cipher text before restoration
    printf("\nCipher text sebelum dikembalikan :\n");
    printList(head);
    printf("\n");

    // Remove karakter yang disisipkan
    removeNodesWithData(&head, '.');

    // Output cipher text before restoration
    printf("\nCipher text setelah penghapusan karakter :\n");
    printList(head);
    printf("\n");

    // Restore original order before decryption
    restoreOriginalOrder(&head);

    // Output cipher text after restoration
    printf("\nCipher text setelah pengembalian (restore order) :\n");
    printList(head);
    printf("\n");

    // Decryption
    uint8_t decrypted_text[AES_BLOCK_SIZE]; // Output
    Node* current = head;
    for (int i = 0; i < AES_BLOCK_SIZE; i++) {
        ciphertext[i] = current->data;
        current = current->next;
    }

    aes_decrypt_128(roundkeys, ciphertext, decrypted_text);

    // Output decrypted text
    printf("\nDecrypted text:\n");
    for (int i = 0; i < AES_BLOCK_SIZE; i++) {
        printf("%c", decrypted_text[i]);
    }
    printf("\n");

    // Simpan teks yang telah terdekripsi ke dalam file
    char outputFileName[512];
    char* baseName = strrchr(inputFileName, '/');
    if (baseName) {
        baseName++;
    }
    else {
        baseName = inputFileName;
    }
    snprintf(outputFileName, sizeof(outputFileName), "%s/decrypted_%s", outputDirectory, baseName);
    FILE* outputFile = fopen(outputFileName, "wb");
    if (!outputFile) {
        printf("[ERROR] Gagal menyimpan teks terdekripsi ke dalam file '%s'.\n", outputFileName);
        return 1; // Gagal menyimpan teks terdekripsi ke dalam file
    }
    fwrite(decrypted_text, 1, AES_BLOCK_SIZE, outputFile);
    fclose(outputFile);

    remove(fullInputPath);

    printf("\n[SUCCESS] Teks terdekripsi telah disimpan di '%s'\n", outputFileName);

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

    //banner();
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
            //banner();
            printf("+----------------------------------+\n");
            printf("|              Enkripsi            |\n");
            printf("+----------------------------------+\n\n");

            encrypt = impEncrypt();
            isValid = true;
            break;
        case 2:
            system("cls");
            //banner();
            printf("+--------------------------------+\n");
            printf("|            Deskripsi           |\n");
            printf("+--------------------------------+\n");

            decrypt = impDecrypt();
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

// Function to create a new node
Node* createNode(char data) {
    Node* newNode = (Node*)malloc(sizeof(Node));
    if (newNode == NULL) {
        printf("Memory allocation failed\n");
        exit(1);
    }
    newNode->data = data;
    newNode->next = NULL;
    newNode->prev = NULL;
    return newNode;
}

// Function to insert a node at the end of the list
void insertEnd(Node** head, char data) {
    Node* newNode = createNode(data);
    if (*head == NULL) {
        *head = newNode;
        (*head)->next = *head;
        (*head)->prev = *head;
    }
    else {
        Node* last = (*head)->prev;
        last->next = newNode;
        newNode->prev = last;
        newNode->next = *head;
        (*head)->prev = newNode;
    }
}

// Function to delete a node from the list
void deleteNode(Node** head, Node* delNode) {
    if (*head == NULL || delNode == NULL) return;

    if (*head == delNode) {
        *head = (*head)->next;
    }

    if (delNode->next != NULL) {
        delNode->next->prev = delNode->prev;
    }

    if (delNode->prev != NULL) {
        delNode->prev->next = delNode->next;
    }

    free(delNode);
}

// Function to insert a character after each node in the list
void insertAfterEachNode(Node** head, char data) {
    if (*head == NULL) return;

    Node* current = *head;

    do {
        Node* newNode = createNode(data);
        Node* temp = current->next; // Simpan node berikutnya sementara
        current->next = newNode; // Sisipkan node baru setelah node saat ini
        newNode->prev = current;
        newNode->next = temp;
        if (temp != NULL) {
            temp->prev = newNode;
        }
        current = temp; // Lanjut ke node berikutnya
    } while (current != *head);
}

// Function to remove every second node in the list
void removeNodesWithData(Node** head, char data) {
    if (*head == NULL) return;

    Node* current = *head;

    do {
        if (current->data == data) {
            Node* temp = current;
            if (temp->prev != NULL) {
                temp->prev->next = temp->next;
            }
            if (temp->next != NULL) {
                temp->next->prev = temp->prev;
            }
            // Update head if necessary
            if (temp == *head) {
                *head = temp->next;
            }
            current = temp->next;
            free(temp);
        }
        else {
            current = current->next;
        }
    } while (current != *head && current != NULL);
}

// Function to shuffle the list using Fisher-Yates algorithm
void shuffleNode(Node** head) {
    if (*head == NULL || (*head)->next == *head) return;

    Node* current = *head;
    int length = 0;

    // Counting the number of elements in the list
    do {
        length++;
        current = current->next;
    } while (current != *head);

    // Perform right shift shuffle
    current = *head;
    for (int i = 0; i < length - 1; i++) {
        char temp = current->data;
        current->data = current->prev->data;
        current->prev->data = temp;
        current = current->next;
    }
}

// Function to restore the original order of the list
void restoreOriginalOrder(Node** head) {
    if (*head == NULL || (*head)->next == *head) return;

    Node* current = (*head)->prev;
    do {
        Node* temp = current->next;
        current->next = current->prev;
        current->prev = temp;
        current = current->next;
    } while (current != (*head)->prev);

    // Move head pointer to the original head node
    *head = (*head)->prev;
}


// Function to print the circular doubly linked list
void printList(Node* head) {
    if (head == NULL) return;

    Node* current = head;

    do {
        printf("%c ", current->data);
        current = current->next;
    } while (current != head);

    printf("\n");
}

// Fungsi untuk mengatur posisi kursor di konsol
void SetPost(int row, int column)
{
    HANDLE consoleHandle;      // Mendeklarasikan variabel untuk menangani konsol
    COORD cursorPosition;      // Mendeklarasikan variabel untuk menyimpan koordinat kursor
    cursorPosition.Y = row;    // Mengatur posisi baris kursor (sumbu Y) sesuai dengan parameter row
    cursorPosition.X = column; // Mengatur posisi kolom kursor (sumbu X) sesuai dengan parameter column
    consoleHandle = GetStdHandle(STD_OUTPUT_HANDLE); // Mendapatkan handle standar untuk output konsol
    SetConsoleCursorPosition(consoleHandle, cursorPosition); // Mengatur posisi kursor di konsol sesuai dengan koordinat yang ditentukan
}

// Fungsi untuk mengatur warna teks di konsol
void SetTextColor(int foregroundColor, int backgroundColor)
{
    HANDLE consoleHandle = GetStdHandle(STD_OUTPUT_HANDLE); // Mendapatkan handle standar untuk output konsol
    SetConsoleTextAttribute(consoleHandle, foregroundColor | backgroundColor); // Mengatur atribut teks konsol (warna teks dan/atau latar belakang)
}

// Fungsi untuk mengembalikan warna teks ke pengaturan default
void ResetTextColor()
{
    HANDLE consoleHandle = GetStdHandle(STD_OUTPUT_HANDLE); // Mendapatkan handle standar untuk output konsol
    SetConsoleTextAttribute(consoleHandle, 0 | 7); // Mengatur atribut teks konsol ke warna default (latar belakang hitam dan teks putih)
}


void banner()
{
    SetTextColor(NONE, FG_YELLOW);
    SetPost(0, 4); printf("%c%c%c%c%c%c%c%c%c%c%c%c  %c%c%c%c%c%c  %c%c%c\n", 219, 219, 219, 219, 219, 219, 219, 187, 219, 219, 219, 187, 219, 219, 187, 219, 219, 187, 219, 219, 187, 219, 219, 219, 219, 219, 219, 187, 219, 219, 187, 219, 219, 219, 219, 219, 219, 187, 219, 219, 219, 219, 219, 219, 219, 187);
    SetPost(1, 4); printf("%c%c%c%c%c%c%c%c%c%c%c%c%c %c%c%c%c%c%c %c%c%c%c\n", 219, 219, 201, 205, 205, 205, 205, 188, 219, 219, 219, 219, 187, 219, 219, 186, 219, 219, 186, 219, 219, 201, 188, 219, 219, 201, 205, 205, 219, 219, 186, 219, 219, 186, 219, 219, 201, 205, 205, 219, 219, 186, 219, 219, 201, 205, 205, 205, 205, 205, 188);
    SetPost(2, 4); printf("%c%c%c%c%c%c  %c%c%c%c%c%c%c%c%c%c%c%c%c%c%c%c\n", 219, 219, 219, 219, 219, 187, 219, 219, 186, 219, 219, 187, 219, 219, 186, 219, 219, 219, 219, 219, 201, 188, 219, 219, 219, 219, 219, 219, 201, 188, 219, 219, 186, 219, 219, 219, 219, 219, 219, 201, 188, 219, 219, 219, 219, 219, 219, 187);
    SetPost(3, 4); printf("%c%c%c%c%c%c  %c%c%c %c%c%c%c%c%c%c%c%c%c%c%c\n", 219, 219, 201, 205, 205, 188, 219, 219, 186, 219, 219, 219, 219, 186, 219, 219, 201, 205, 219, 219, 187, 219, 219, 201, 205, 219, 219, 186, 219, 219, 186, 219, 219, 201, 205, 205, 205, 188, 200, 205, 205, 205, 205, 219, 219, 187);
    SetPost(4, 4); printf("%c%c%c%c%c%c%c%c%c%c%c  %c%c%c%c%c%c%c  %c%c%c\n", 219, 219, 219, 219, 219, 219, 219, 187, 219, 219, 186, 219, 219, 219, 186, 219, 219, 186, 219, 219, 187, 219, 219, 186, 219, 219, 187, 219, 219, 186, 219, 219, 186, 219, 219, 219, 219, 219, 219, 219, 201, 188);
    SetPost(5, 4); printf("%c%c%c%c%c%c%c%c%c%c%c  %c%c%c%c%c%c%c  %c%c%c\n", 200, 205, 205, 205, 205, 205, 205, 188, 200, 205, 188, 200, 205, 205, 188, 200, 205, 188, 200, 205, 188, 200, 205, 188, 200, 205, 188, 200, 205, 188, 200, 205, 188, 200, 205, 205, 205, 205, 205, 205, 188);
    ResetTextColor();
}