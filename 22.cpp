#include <stdio.h>
#include <stdint.h>
#include <string.h>

// S-DES key length and block size
#define SDES_KEY_SIZE 10
#define SDES_BLOCK_SIZE 8

// S-DES S-boxes (4-bit input -> 2-bit output)
const uint8_t sbox0[4][4] = {
    {1, 0, 3, 2},
    {3, 2, 1, 0},
    {0, 2, 1, 3},
    {3, 1, 3, 2}
};

const uint8_t sbox1[4][4] = {
    {0, 1, 2, 3},
    {2, 0, 1, 3},
    {3, 0, 1, 0},
    {2, 1, 0, 3}
};

// Permutation P10
const uint8_t p10[10] = {2, 4, 1, 6, 3, 9, 0, 8, 7, 5};

// Permutation P8
const uint8_t p8[8] = {5, 2, 6, 3, 7, 4, 9, 8};

// Initial permutation IP
const uint8_t ip[8] = {1, 5, 2, 0, 3, 7, 4, 6};

// Inverse initial permutation IP^-1
const uint8_t ip_inv[8] = {3, 0, 2, 4, 6, 1, 7, 5};

// Expansion E/P
const uint8_t ep[8] = {3, 0, 1, 2, 1, 2, 3, 0};

// Straight permutation P4
const uint8_t p4[4] = {1, 3, 2, 0};

// Function prototypes
void sdes_key_schedule(const uint8_t *key, uint8_t *k1, uint8_t *k2);
void sdes_encrypt(const uint8_t *plaintext, const uint8_t *key, const uint8_t *iv, uint8_t *ciphertext);
void sdes_decrypt(const uint8_t *ciphertext, const uint8_t *key, const uint8_t *iv, uint8_t *plaintext);
void initial_permutation(const uint8_t *input, uint8_t *output, const uint8_t *perm);
void inverse_permutation(const uint8_t *input, uint8_t *output, const uint8_t *perm);
void permutation(const uint8_t *input, uint8_t *output, const uint8_t *perm, int size);
void expansion_permutation(const uint8_t *input, uint8_t *output, const uint8_t *perm, int size);
void sbox(const uint8_t *input, uint8_t *output, const uint8_t sbox[4][4], int size);
void xor_bits(uint8_t *result, const uint8_t *a, const uint8_t *b, int size);

// S-DES key schedule
void sdes_key_schedule(const uint8_t *key, uint8_t *k1, uint8_t *k2) {
    uint8_t temp_key[10];
    permutation(key, temp_key, p10, 10);
    
    // Left circular shift (LS-1)
    uint8_t temp = temp_key[0];
    for (int i = 0; i < 4; i++) {
        temp_key[i] = temp_key[i + 1];
    }
    temp_key[4] = temp;

    // Generate K1
    permutation(temp_key, k1, p8, 8);

    // Left circular shift (LS-2)
    temp = temp_key[5];
    temp_key[5] = temp_key[6];
    temp_key[6] = temp;
    temp = temp_key[7];
    temp_key[7] = temp_key[8];
    temp_key[8] = temp;

    // Generate K2
    permutation(temp_key, k2, p8, 8);
}

// S-DES encryption
void sdes_encrypt(const uint8_t *plaintext, const uint8_t *key, const uint8_t *iv, uint8_t *ciphertext) {
    uint8_t k1[8], k2[8];
    uint8_t temp[SDES_BLOCK_SIZE], temp2[SDES_BLOCK_SIZE];

    // Generate subkeys
    sdes_key_schedule(key, k1, k2);

    // Initial permutation (IP)
    initial_permutation(plaintext, temp, ip);

    // XOR with IV for CBC mode
    xor_bits(temp, temp, iv, SDES_BLOCK_SIZE);

    // Round 1: Fk1
    expansion_permutation(temp, temp2, ep, 8);
    xor_bits(temp2, temp2, k1, 8);
    sbox(temp2, temp, sbox0, 4);
    permutation(temp, temp, p4, 4);
    xor_bits(temp, temp, &temp2[4], 4);

    // Round 2: Fk2
    expansion_permutation(temp, temp2, ep, 8);
    xor_bits(temp2, temp2, k2, 8);
    sbox(temp2, temp, sbox1, 4);
    permutation(temp, temp, p4, 4);
    xor_bits(temp, temp, &temp2[4], 4);

    // Final permutation (IP^-1)
    inverse_permutation(temp, ciphertext, ip_inv);
}

// S-DES decryption
void sdes_decrypt(const uint8_t *ciphertext, const uint8_t *key, const uint8_t *iv, uint8_t *plaintext) {
    uint8_t k1[8], k2[8];
    uint8_t temp[SDES_BLOCK_SIZE], temp2[SDES_BLOCK_SIZE];

    // Generate subkeys
    sdes_key_schedule(key, k1, k2);

    // Initial permutation (IP)
    initial_permutation(ciphertext, temp, ip);

    // Round 1: Fk2
    expansion_permutation(temp, temp2, ep, 8);
    xor_bits(temp2, temp2, k2, 8);
    sbox(temp2, temp, sbox1, 4);
    permutation(temp, temp, p4, 4);
    xor_bits(temp, temp, &temp2[4], 4);

    // Round 2: Fk1
    expansion_permutation(temp, temp2, ep, 8);
    xor_bits(temp2, temp2, k1, 8);
    sbox(temp2, temp, sbox0, 4);
    permutation(temp, temp, p4, 4);
    xor_bits(temp, temp, &temp2[4], 4);

    // Final permutation (IP^-1)
    inverse_permutation(temp, plaintext, ip_inv);

    // XOR with IV for CBC mode
    xor_bits(plaintext, plaintext, iv, SDES_BLOCK_SIZE);
}

// Initial permutation
void initial_permutation(const uint8_t *input, uint8_t *output, const uint8_t *perm) {
    permutation(input, output, perm, 8);
}

// Inverse initial permutation
void inverse_permutation(const uint8_t *input, uint8_t *output, const uint8_t *perm) {
    permutation(input, output, perm, 8);
}

// General permutation function
void permutation(const uint8_t *input, uint8_t *output, const uint8_t *perm, int size) {
    for (int i = 0; i < size; i++) {
        output[i] = (input[(perm[i] / 8)] >> (7 - (perm[i] % 8))) & 1;
    }
}

// Expansion permutation (E/P)
void expansion_permutation(const uint8_t *input, uint8_t *output, const uint8_t *perm, int size) {
    for (int i = 0; i < size; i++) {
        output[i] = input[perm[i]];
    }
}

// S-box substitution

