#ifndef ENKRIPSIANA_H
#define ENKRIPSIANA_H

#include <stdio.h>
#include <stdint.h>


#define AES_BLOCK_SIZE      16
#define AES_KEY_SIZE		16
#define AES_ROUNDS          10  // 12, 14
#define AES_ROUND_KEY_SIZE  176 // AES-128 has 10 rounds, and there is a AddRoundKey before first round. (10+1)x16=176.

/*
* Linked list node structure
*/
typedef struct Node {
    char data;
    struct Node* next;
    struct Node* prev;
} Node;


static uint8_t RC[] = { 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36 };

/**
 * @purpose:            Key schedule for AES-128
 * @par[in]key:         16 bytes of master keys
 * @par[out]roundkeys:  176 bytes of round keys
 */
void aes_key_schedule_128(const uint8_t* key, uint8_t* roundkeys);

/*
 *
 * @purpose:        File operation (read, write)
 * 
 */
char* readFile(const char* fileName);
int readFileDataByte(const char* filename, uint8_t* buffer, size_t buffer_size);
int writeFile(const char* fileName, const void* data, size_t dataSize);
int writeFileByte(const char* filename, uint8_t* data, size_t data_size);
int writeListToFile(const char* fileName, Node* head);
void listFilesInDirectory(const char* directory);
int fileExists(const char* filename);

/*
 *
 * @purpose:        Linked List
 *
 */
Node* createNode(char data);
void insertEnd(Node** head, char data);
void deleteNode(Node** head, Node* delNode);
void printList(Node* head);

/*
 *
 * @purpose:        UI or Navigation
 *
 */
void mainMenu();
void backOrExit();

#endif
