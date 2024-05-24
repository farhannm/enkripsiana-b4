#pragma warning(disable : 4996)
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <ctime>
#include "enkripsiana.h"
#include "dirent.h"
#include "uihead.h"
#include "Encrypt.h"
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

int impEncrypt() {
    const char* inputDirectory = "Plain"; // Input Dir
    const char* outputDirectory = "Encrypted"; // Output Dir
    char key[17]; // 16 karakter untuk kunci AES dan 1 karakter untuk null-terminator

    uint8_t roundkeys[AES_ROUND_KEY_SIZE]; // Key schedule

    uint8_t ciphertext[AES_BLOCK_SIZE]; // Output

    DIR* dir = opendir(inputDirectory);
    if (!dir) {
        printf("\033[1;31m[ERROR] Direktori tidak ditemukan atau tidak dapat diakses.\033[0m\n");
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
        printf("[\033[1;36mINFO\033[0m] Tidak ada file yang ditemukan dalam direktori.\n");
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
        printf("\n[\033[1;32mINPUT\033[0m] Masukkan nomor indeks file yang akan dienkripsi : ");
        if (scanf("%d", &fileIndex) != 1) {
            printf("\033[1;31m[ERROR] Masukkan nomor indeks yang valid.\033[0m\n");
            while (getchar() != '\n'); // Membersihkan input buffer
        }
        else if (fileIndex < 1 || fileIndex > fileCount) {
            printf("\033[1;31m[ERROR] Nomor indeks tidak valid.\033[0m\n");
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
        printf("\033[1;31m[ERROR] Gagal membaca plain text dari file '%s'.\033[0m\n", fullInputPath);
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
    printf("[\033[1;32mINPUT\033[0m] Masukkan kunci (perlu 16 karakter): ");
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
        printf("\n\033[1;33m[WARNING] Kunci harus memiliki panjang 16 karakter\033[0m\n\n");
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
        printf("\033[1;31m[ERROR] Gagal menyimpan hasil pengacakan ke dalam file '%s'.\033[0m\n", outputFileName);
        free(plain_text);
        free(padded_text);
        return 1;
    }

    remove(fullInputPath);

    printf("\033[1;32m[SUCCESS] File berhasil dienkripsi. Enkripsi tersimpan di '%s'\033[0m\n", outputFileName);

    free(plain_text);
    free(padded_text);

    backOrExit();

    return 0;
}

