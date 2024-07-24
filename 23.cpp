#include <stdio.h>
#include <stdint.h>

// Initial permutation table for S-DES
const int IP[] = {1, 5, 2, 0, 3, 7, 4, 6};

// Inverse initial permutation table
const int IP_INV[] = {3, 0, 2, 4, 6, 1, 7, 5};

// Expansion permutation table
const int EP[] = {3, 0, 1, 2, 1, 2, 3, 0};

// Permutation P4
const int P4[] = {1, 3, 2, 0};

// S-boxes (S0 and S1)
const int S0[4][4] = {
    {1, 0, 3, 2},
    {3, 2, 1, 0},
    {0, 2, 1, 3},
    {3, 1, 3, 2}
};

const int S1[4][4] = {
    {0, 1, 2, 3},
    {2, 0, 1, 3},
    {3, 0, 1, 0},
    {2, 1, 0, 3}
};

// Permutation P10
const int P10[] = {2, 4, 1, 6, 3, 9, 0, 8, 7, 5};

// Permutation P8
const int P8[] = {5, 2, 6, 3, 7, 4, 9, 8};

// Left shift for key generation
const int LS[] = {1, 2};

// Key variables
uint8_t key[10];
uint8_t key1[8], key2[8];

// Function to perform permutation
uint8_t permute(uint8_t input, const int *perm, int size) {
    uint8_t output = 0;
    for (int i = 0; i < size; ++i) {
        output |= ((input >> (7 - perm[i])) & 0x01) << (size - 1 - i);
    }
    return output;
}

// Function to generate subkeys
void generate_subkeys() {
    uint8_t temp = permute(*(uint16_t *)key, P10, 10);
    
    // Split into two parts
    uint8_t left = temp >> 5;
    uint8_t right = temp & 0x1F;
    
    // Perform left shifts
    for (int i = 0; i < 2; ++i) {
        left = ((left << LS[i]) | (left >> (5 - LS[i]))) & 0x1F;
        right = ((right << LS[i]) | (right >> (5 - LS[i]))) & 0x1F;
    }
    
    // Combine and permute to get key1
    uint8_t combined = (left << 5) | right;
    *(uint16_t *)key1 = permute(combined, P8, 8);
    
    // Perform left shifts again for key2
    left = ((left << 1) | (left >> 4)) & 0x1F;
    right = ((right << 1) | (right >> 4)) & 0x1F;
    
    combined = (left << 5) | right;
    *(uint16_t *)key2 = permute(combined, P8, 8);
}

// Function to perform S-DES encryption
uint8_t sdes_encrypt(uint8_t plaintext, uint8_t counter) {
    // Initial permutation
    uint8_t permuted = permute(plaintext, IP, 8);
    
    // Generate key based on counter
    key[0] = counter;
    generate_subkeys();
    
    // Perform initial round
    uint8_t round_output = permuted ^ key1[0];
    
    // Apply EP and split into left and right
    uint8_t left = round_output >> 4;
    uint8_t right = round_output & 0x0F;
    
    // Apply S-boxes
    uint8_t sbox_input1 = permute(left, EP, 4);
    uint8_t sbox_input2 = permute(right, EP, 4);
    
    uint8_t sbox_output1 = (S0[(sbox_input1 >> 2)][(sbox_input1 & 0x03)] << 2) |
                           S1[(sbox_input2 >> 2)][(sbox_input2 & 0x03)];
    
    // Apply P4 permutation
    uint8_t p4_output = permute(sbox_output1, P4, 4);
    
    // XOR with left part of permuted
    uint8_t new_left = permuted >> 4;
    uint8_t new_right = permuted & 0x0F;
    
    new_left ^= p4_output;
    
    // Final swap and permutation
    uint8_t final_output = (new_right << 4) | new_left;
    final_output = permute(final_output, IP_INV, 8);
    
    return final_output;
}

// Function to perform S-DES decryption (not used in this example)
uint8_t sdes_decrypt(uint8_t ciphertext, uint8_t counter) {
    // Decryption is the same as encryption for S-DES in counter mode
    return sdes_encrypt(ciphertext, counter);
}

int main() {
    // Test data
    uint8_t plaintext[] = {0x01, 0x02, 0x04}; // 0000 0001 0000 0010 0000 0100
    uint8_t key[] = {0x7D};                   // 0111 1101
    uint8_t counter = 0x00;                   // Starting counter
    
    printf("Plaintext: ");
    for (int i = 0; i < sizeof(plaintext); ++i) {
        printf("%02x ", plaintext[i]);
    }
    printf("\n");

    // Encrypt each byte of plaintext
    printf("Encrypting...\n");
    for (int i = 0; i < sizeof(plaintext); ++i) {
        uint8_t encrypted = sdes_encrypt(plaintext[i], counter);
        printf("Counter: %02x, Encrypted: %02x\n", counter, encrypted);
        counter++; // Increment counter for next block
    }
    
return 0;


}

