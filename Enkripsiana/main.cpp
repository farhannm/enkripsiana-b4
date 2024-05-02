#include <stdio.h>
#include <string.h>
#include "enkripsiana.h"

int main(int argc, char* argv[]) {
    char plain_text[AES_BLOCK_SIZE + 1]; // 16 karakter untuk plaintext dan 1 karakter untuk null-terminator
    char key[17]; // 16 karakter untuk kunci AES dan 1 karakter untuk null-terminator

    // Padding jika panjang input kurang dari 16 karakter
    int key_padding_len = AES_KEY_SIZE - strlen(key);
    // Padding jika panjang input kurang dari 16 karakter
    int plaintxt_padding_len = AES_BLOCK_SIZE - strlen(plain_text);

    uint8_t roundkeys[AES_ROUND_KEY_SIZE]; // Key schedule

    uint8_t ciphertext[AES_BLOCK_SIZE]; // Output

    uint8_t decrypted_text[AES_BLOCK_SIZE]; // Output

    while (1) {
        printf("[INPUT] Masukkan plain text (perlu 16 karakter): ");
        fgets(plain_text, sizeof(plain_text), stdin);
        if (strlen(plain_text) == 16) {
            break; // Keluar dari loop jika panjang plain text sesuai
        }
        else {
            printf("\n[WARNING] Plain text harus memiliki panjang 16 karakter\n");
        }
    }

    for (int i = 0; i < key_padding_len; ++i) {
        strcat_s(key, " ");
    }

    // Input key
    while (1) {
        printf("[INPUT] Masukkan kunci (perlu 16 karakter): ");
        fgets(key, sizeof(key), stdin);
        if (strlen(key) == 16) {
            break; // Keluar dari loop jika panjang kunci sesuai
        }
        else {
            printf("\n[WARNING] Kunci harus memiliki panjang 16 karakter\n");
        }
    }

    for (int i = 0; i < plaintxt_padding_len; ++i) {
        strcat_s(plain_text, " ");
    }

    aes_key_schedule_128((uint8_t*)key, roundkeys);

    // Encryption
    aes_encrypt_128(roundkeys, (uint8_t*)plain_text, ciphertext);

    // Output cipher text
    printf("\nCipher text:\n");
    for (int i = 0; i < AES_BLOCK_SIZE; i++) {
        printf("%c ", ciphertext[i]);
    }
    printf("\n");

    // Decryption
    aes_decrypt_128(roundkeys, ciphertext, decrypted_text);

    // Output decrypted text
    printf("\nDecrypted text:\n");
    for (int i = 0; i < AES_BLOCK_SIZE; i++) {
        printf("%c", decrypted_text[i]);
    }
    printf("\n");

    return 0;
}
