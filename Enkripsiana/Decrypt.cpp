#pragma warning(disable : 4996)
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <ctime>
#include "enkripsiana.h"
#include "dirent.h"
#include "uihead.h"
#include "Decrypt.h"

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


int impDecrypt() {
    const char* inputDirectory = "Encrypted"; // Input Dir
    const char* outputDirectory = "Decrypted"; // Output Dir
    char key[17]; // 16 karakter untuk kunci AES dan 1 karakter untuk null-terminator

    uint8_t roundkeys[AES_ROUND_KEY_SIZE]; // Key schedule

    // Memeriksa apakah direktori "Encrypted" memiliki file
    DIR* dir = opendir(inputDirectory);
    if (!dir) {
        printf("\033[1;31m[ERROR] Direktori tidak ditemukan atau tidak dapat diakses.\033[0m\n");
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
        printf("\n[\033[1;36mINFO\033[0m] Tidak ada file yang ditemukan dalam direktori.\n");
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

    int opsi;
    bool isValid;

    do {
        printf("\n[\033[1;36mINFO\033[0m] Pilihan aksi\n\n");
        printf("(1). Kembali ke menu utama \n");
        printf("(2). Pilih indeks file \n");
        printf("\n[\033[1;32m>>\033[0m] Masukkan pilihan (1/2) : ");

        if (scanf("%d", &opsi) == 1) {
            switch (opsi) {
            case 1:
                system("cls");
                mainMenu();
                isValid = true;
                break;
            case 2: {
                // Meminta pengguna untuk memasukkan nomor indeks file
                int fileIndex;
                do {
                    printf("\n[\033[1;32mINPUT\033[0m] Masukkan nomor indeks file yang akan didekripsi : ");
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

                // Baca ciphertext dari file yang dipilih
                uint8_t ciphertext[32];
                FILE* inputFile = fopen(fullInputPath, "rb");
                if (!inputFile) {
                    printf("\033[1;31m[ERROR] Gagal membaca ciphertext dari file '%s'.\033[0m\n", fullInputPath);
                    return 1;
                }
                fread(ciphertext, 1, 32, inputFile);
                fclose(inputFile);

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
                    printf("\033[1;31m[ERROR] Gagal menyimpan teks terdekripsi ke dalam file '%s'.\033[0m\n", outputFileName);
                    return 1; // Gagal menyimpan teks terdekripsi ke dalam file
                }
                fwrite(decrypted_text, 1, AES_BLOCK_SIZE, outputFile);
                fclose(outputFile);

                remove(fullInputPath);

                printf("\n\033[1;32m[SUCCESS] Teks terdekripsi telah disimpan di '%s'\033[0m\n", outputFileName);

                backOrExit();
                isValid = true;
                break;
            }
            default:
                printf("\n\033[1;31mInput tidak valid. Masukkan angka antara 1 atau 2.\033[0m\n");
                isValid = false;
                break;
            }
        }
        else {
            printf("\n\033[1;31mInput tidak valid. Masukkan angka antara 1 atau 2.\033[0m\n");
            isValid = false;
            // Bersihkan buffer input
            while (getchar() != '\n');
        }

    } while (!isValid);

    return 0;
}
