#pragma warning(disable : 4996)
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <ctime>
#include "enkripsiana.h"
#include "dirent.h"
#include "uihead.h"
#include "Decrypt.h"
#include "Encrypt.h"

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
char* readFile(const char* fileName) {
    FILE* file = fopen(fileName, "r");
    if (!file) {
        printf("\033[1;31m[ERROR] Gagal membuka file '%s' untuk dibaca.\033[0m\n", fileName);
        return NULL;
    }

    fseek(file, 0, SEEK_END);
    long fileSize = ftell(file);
    fseek(file, 0, SEEK_SET);

    char* buffer = (char*)malloc(fileSize + 1);
    if (!buffer) {
        printf("\033[1;31m[ERROR] Gagal mengalokasikan memori untuk file '%s'.\033[0m\n", fileName);
        fclose(file);
        return NULL;
    }

    size_t elementsRead = fread(buffer, fileSize, 1, file);
    fclose(file);

    if (elementsRead != 1) {
        printf("\033[1;31m[ERROR] Gagal membaca file '%s'.\033[0m\n", fileName);
        free(buffer);
        return NULL;
    }

    buffer[fileSize] = '\0';
    return buffer;
}

int readFileDataByte(const char* filename, uint8_t* buffer, size_t buffer_size) {
    FILE* file = fopen(filename, "rb"); // Buka file dalam mode binary read

    if (!file) {
        printf("\033[1;31m[ERROR] Gagal membuka file '%s' untuk dibaca.\033[0m\n", filename);
        return 0; // Gagal membuka file
    }

    // Membaca data dari file ke dalam buffer
    size_t bytes_read = fread(buffer, 1, buffer_size, file);

    fclose(file); // Tutup file

    // Periksa apakah jumlah byte yang dibaca sesuai dengan buffer_size
    if (bytes_read != buffer_size) {
        printf("\033[1;31m[ERROR] Gagal membaca data dari file '%s'.\033[0m\n", filename);
        return 0; // Gagal membaca data dari file
    }

    return 1; // Berhasil membaca data dari file
}

// Function to write the contents of a buffer to a file
int writeFile(const char* fileName, const void* data, size_t dataSize) {
    FILE* file = fopen(fileName, "w");
    if (!file) {
        printf("\033[1;31m[ERROR] Gagal membuka file '%s' untuk ditulis.\033[0m\n", fileName);
        return 0;
    }

    size_t elementsWritten = fwrite(data, dataSize, 1, file);
    fclose(file);

    if (elementsWritten != 1) {
        printf("\033[1;31m[ERROR] Gagal menulis ke file '%s'.\033[0m\n", fileName);
        return 0;
    }

    return 1;
}

// Fungsi untuk menulis data ke dalam file
int writeFileByte(const char* filename, uint8_t* data, size_t data_size) {
    FILE* file = fopen(filename, "wb"); // Buka file dalam mode binary write

    if (!file) {
        printf("\033[1;31m[ERROR] Gagal membuka file '%s' untuk ditulis.\033[0m\n", filename);
        return 0; // Gagal membuka file
    }

    // Menulis data ke dalam file
    size_t bytes_written = fwrite(data, 1, data_size, file);

    fclose(file); // Tutup file

    // Periksa apakah jumlah byte yang ditulis sesuai dengan data_size
    if (bytes_written != data_size) {
        printf("\033[1;31m[ERROR] Gagal menulis data ke dalam file '%s'.\033[0m\n", filename);
        return 0; // Gagal menulis data ke dalam file
    }

    return 1; // Berhasil menulis data ke dalam file
}

int writeListToFile(const char* fileName, Node* head) {
    FILE* file = fopen(fileName, "w");
    if (!file) {
        printf("\033[1;31m[ERROR] Gagal membuka file '%s' untuk ditulis.\033[0m\n", fileName);
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
        printf("[\033[1;32mINFO\033[0m] Daftar file di direktori : \n", directory);
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
        perror("\033[1;31m[!] Gagal membuka direktori.\033[0m");
    }
}

char* padPlainText(const char* plain_text) {
    // Padding jika panjang plaintext kurang dari 16 karakter
    int padding_len = AES_BLOCK_SIZE - strlen(plain_text);
    char* padded_text = (char*)malloc(AES_BLOCK_SIZE + 1); // 1 extra for null-terminator
    if (!padded_text) {
        printf("\033[1;31m[ERROR] Memory allocation failed.\033[0m\n");
        return NULL;
    }
    strcpy(padded_text, plain_text);
    for (int i = 0; i < padding_len; ++i) {
        strcat(padded_text, " ");
    }
    return padded_text;
}


// Function to create a new node
Node* createNode(char data) {
    Node* newNode = (Node*)malloc(sizeof(Node));
    if (newNode == NULL) {
        printf("\033[1;31m[ERROR] Memory allocation failed.\033[0m\n");
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

void backOrExit() {
    int opsi;
    bool isValid;

    do {
        printf("\n[\033[1;32mINFO\033[0m] Proses selesai\n\n");
        printf("(1). Kembali ke menu utama \n");
        printf("(2). Keluar dari aplikasi \n");
        printf("\n[\033[1;32m>>\033[0m] Masukkan pilihan (1/2) : ");

        if (scanf("%d", &opsi) == 1) {
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
                printf("\n\033[1;31mInput tidak valid. Masukkan angka antara 1 hingga 2.\033[0m\n");
                isValid = false;
                break;
            }
        }
        else {
            printf("\n\033[1;31mInput tidak valid. Masukkan angka antara 1 hingga 2.\033[0m\n");
            isValid = false;
            // Bersihkan buffer input
            while (getchar() != '\n');
        }

    } while (!isValid);
}

void mainMenu() {
    int opsi, encrypt, decrypt;
    bool isValid;

    banner();
    SetTextColor(NONE, FG_LIGHT_YELLOW);
    SetPost(10, 47); printf("%c%c%c%c%c%c%c%c%c%c%c%c%c%c%c%c%c%c%c%c%c%c%c%c%c%c%c%c%c%c%c%c%c%c%c%c%c%c%c%c%c%c\n", 201, 205,205,205,205, 205, 205, 205, 205,205,205, 205, 205, 205, 205, 205, 205,205,205,205,205,205,205,205,205,205,205, 205, 205, 205, 205, 205, 205, 205, 205, 205, 205, 205, 205, 205, 205, 187);
    SetPost(11, 47); printf("%c            M A I N  M E N U            %c\n", 186,186);
    SetPost(12, 47); printf("%c%c%c%c%c%c%c%c%c%c%c%c%c%c%c%c%c%c%c%c%c%c%c%c%c%c%c%c%c%c%c%c%c%c%c%c%c%c%c%c%c%c\n", 200, 205,205,205,205, 205, 205, 205, 205,205,205, 205, 205, 205, 205, 205, 205, 205, 205,205,205,205,205,205,205,205,205,205,205, 205, 205, 205, 205, 205, 205, 205, 205, 205, 205, 205, 205, 188);

    do {
        SetPost(13, 52); printf("Pilih aksi yang akan dilakukan : \n");
        SetPost(14, 52); printf("(1). Enkripsi \n");
        SetPost(15, 52); printf("(2). Deskripsi\n");
        SetPost(16, 52); printf("(3). Keluar dari aplikasi \n");
        ResetTextColor();
        printf("\n[\033[1;32m>>\033[0m] Masukkan pilihan (1-3) : ");

        if (scanf("%d", &opsi) == 1) {
            switch (opsi) {
            case 1:
                system("cls");
                banner();
                printf("+----------------------------------+\n");
                printf("|              Enkripsi            |\n");
                printf("+----------------------------------+\n");

                encrypt = impEncrypt();
                isValid = true;
                break;
            case 2:
                system("cls");
                banner();
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
                printf("\n\033[1;31mInput tidak valid. Masukkan angka antara 1 hingga 3.\033[0m\n");
                isValid = false;
                break;
            }
        }
        else {
            printf("\n\033[1;31mInput tidak valid. Masukkan angka antara 1 hingga 3.\033[0m\n");
            isValid = false;
            // Bersihkan buffer input
            while (getchar() != '\n');
        }

    } while (!isValid);
}
