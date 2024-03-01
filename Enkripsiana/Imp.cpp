#pragma warning(disable : 4996)
#include <stdio.h>
#include <stdint.h>
#include <string.h>

#define AES_256_KEY_LENGTH 32
#define AES_BLOCK_SIZE 192

// Key expansion algorithm
void keyExpansion(const uint8_t* key, uint8_t* roundKeys) {
    uint32_t* w = (uint32_t*)roundKeys;

    // Copy the key directly 
    memcpy(w, key, AES_256_KEY_LENGTH);

    for (int i = 8; i < 60; ++i) {
        uint32_t temp = w[i - 1];

        if (i % 8 == 0) {
            // RotWord + SubWord
            temp = ((temp << 8) & 0xFFFFFF00) | ((temp >> 24) & 0x000000FF);
            temp = ((temp & 0xFF00FF00) | (temp & 0x00FF00FF)) & 0xFFFFFFFF;
            temp = (temp >> 24) | ((temp >> 8) & 0x0000FF00) | ((temp << 8) & 0x00FF0000) | (temp << 24);
            temp ^= (0x1B << 24);
        }

        w[i] = w[i - 8] ^ temp;
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
    static const uint8_t sBox[256] = {
    0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5,
    0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
    0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0,
    0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0,
    0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC,
    0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
    0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A,
    0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75,
    0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0,
    0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84,
    0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B,
    0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
    0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85,
    0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8,
    0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5,
    0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2,
    0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17,
    0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
    0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88,
    0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB,
    0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C,
    0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79,
    0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9,
    0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
    0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6,
    0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A,
    0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E,
    0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E,
    0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94,
    0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
    0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68,
    0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16
    };


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
            a ^= 0x1B; // XOR with the irreducible polynomial x^8 + x^4 + x^3 + x + 1
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


// AES-256 encryption algorithm
void aes256EncryptBlock(const uint8_t* input, const uint8_t* roundKeys, uint8_t* output) {
    uint8_t state[AES_BLOCK_SIZE];
    memcpy(state, input, AES_BLOCK_SIZE);

    // Initial Round
    addRoundKey(state, roundKeys);

    // Main Rounds
    for (int round = 1; round < 14; ++round) {
        subBytes(state);
        shiftRows(state);
        mixColumns(state);
        addRoundKey(state, roundKeys + (round * AES_BLOCK_SIZE));
    }

    // Final Round
    subBytes(state);
    shiftRows(state);
    addRoundKey(state, roundKeys + 14 * AES_BLOCK_SIZE);

    memcpy(output, state, AES_BLOCK_SIZE);
}

size_t readFile(const char* filename, uint8_t* buffer, size_t bufferSize) {
    FILE* file = fopen(filename, "rb");
    if (!file) {
        perror("Error opening file");
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
        perror("Error opening file");
        return;
    }

    fwrite(buffer, 1, dataSize, file);
    fclose(file);
}

void readPrivateKey(uint8_t* key, size_t keyLength) {
    printf("Enter the private key (must be %zu characters): ", keyLength);
    scanf("%s", key);
}

int main() {
    const char* inputFileName = "input.txt";
    const char* outputFileName = "encrypted_output.txt";
    const size_t keyLength = AES_256_KEY_LENGTH;
    uint8_t key[AES_256_KEY_LENGTH];

    // Read the private key from the user
    readPrivateKey(key, keyLength);

    // Read the contents of the input file
    uint8_t inputData[AES_BLOCK_SIZE];
    size_t bytesRead = readFile(inputFileName, inputData, sizeof(inputData));
    if (bytesRead == 0) {
        return 1;  // Exit with an error code
    }

    // Perform key expansion
    uint8_t roundKeys[15 * AES_BLOCK_SIZE];
    keyExpansion(key, roundKeys);

    // Encrypt the data
    uint8_t encryptedOutput[AES_BLOCK_SIZE];
    aes256EncryptBlock(inputData, roundKeys, encryptedOutput);

    // Write the encrypted data to the output file
    writeFile(outputFileName, encryptedOutput, sizeof(encryptedOutput));

    printf("Encryption successful. Encrypted data written to %s.\n", outputFileName);

    return 0;
}