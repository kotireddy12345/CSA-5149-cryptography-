#include <stdio.h>
#include <stdint.h>
#include <string.h>

// AES block size in bytes
#define AES_BLOCK_SIZE 16

// Function prototypes
void aes128_encrypt(const uint8_t *plaintext, const uint8_t *key, uint8_t *ciphertext);
void xor_blocks(uint8_t *result, const uint8_t *block1, const uint8_t *block2);
void cbc_mac(const uint8_t *message, const uint8_t *key, uint8_t *mac);

// AES-128 encryption (dummy implementation for illustration)
void aes128_encrypt(const uint8_t *plaintext, const uint8_t *key, uint8_t *ciphertext) {
    // Dummy implementation: XOR plaintext with key
    for (int i = 0; i < AES_BLOCK_SIZE; i++) {
        ciphertext[i] = plaintext[i] ^ key[i];
    }
}

// XOR two blocks
void xor_blocks(uint8_t *result, const uint8_t *block1, const uint8_t *block2) {
    for (int i = 0; i < AES_BLOCK_SIZE; i++) {
        result[i] = block1[i] ^ block2[i];
    }
}

// CBC-MAC calculation
void cbc_mac(const uint8_t *message, const uint8_t *key, uint8_t *mac) {
    uint8_t temp[AES_BLOCK_SIZE];
    uint8_t iv[AES_BLOCK_SIZE]; // Initialization vector (all zeros for the first block)

    // Encrypt the message using AES-128 in CBC mode
    aes128_encrypt(message, key, mac); // Initialize with the first block

    // XOR subsequent blocks with the previous ciphertext
    for (int i = AES_BLOCK_SIZE; i < 2 * AES_BLOCK_SIZE; i += AES_BLOCK_SIZE) {
        xor_blocks(temp, mac, &message[i]);
        aes128_encrypt(temp, key, mac);
    }
}

int main() {
    // Example key (16 bytes)
    uint8_t key[AES_BLOCK_SIZE] = {
        0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
        0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c
    };

    // Example one-block message X (16 bytes)
    uint8_t X[AES_BLOCK_SIZE] = {
        0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96,
        0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a
    };

    // Buffer for CBC-MAC result (16 bytes)
    uint8_t T[AES_BLOCK_SIZE];

    // Compute CBC-MAC for message X
    cbc_mac(X, key, T);

    // Print the CBC-MAC (T)
    printf("CBC-MAC (T) for X: ");
    for (int i = 0; i < AES_BLOCK_SIZE; i++) {
        printf("%02x", T[i]);
    }
    printf("\n");

    // Compute CBC-MAC for two-block message X || (X XOR T)
    uint8_t two_block_message[2 * AES_BLOCK_SIZE];
    memcpy(two_block_message, X, AES_BLOCK_SIZE); // Copy X
    xor_blocks(&two_block_message[AES_BLOCK_SIZE], X, T); // Append (X XOR T)

    // Compute CBC-MAC for the two-block message
    cbc_mac(two_block_message, key, T);

    // Print the CBC-MAC (T) for the two-block message
    printf("CBC-MAC (T) for X || (X XOR T): ");
    for (int i = 0; i < AES_BLOCK_SIZE; i++) {
        printf("%02x", T[i]);
    }
    printf("\n");

    return 0;
}

