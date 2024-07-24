#include <stdio.h>
#include <string.h>


#define AES_BLOCK_SIZE 16

// Function to encrypt using AES in ECB mode
void aes_ecb_encrypt(const unsigned char *plaintext, int plaintext_len, unsigned char *key, unsigned char *ciphertext) {
    AES_KEY aes_key;
    AES_set_encrypt_key(key, 128, &aes_key);
    
    for (int i = 0; i < plaintext_len; i += AES_BLOCK_SIZE) {
        AES_encrypt(plaintext + i, ciphertext + i, &aes_key);
    }
}

// Function to decrypt using AES in ECB mode
void aes_ecb_decrypt(const unsigned char *ciphertext, int ciphertext_len, unsigned char *key, unsigned char *plaintext) {
    AES_KEY aes_key;
    AES_set_decrypt_key(key, 128, &aes_key);
    
    for (int i = 0; i < ciphertext_len; i += AES_BLOCK_SIZE) {
        AES_decrypt(ciphertext + i, plaintext + i, &aes_key);
    }
}

// Function to encrypt using AES in CBC mode
void aes_cbc_encrypt(const unsigned char *plaintext, int plaintext_len, unsigned char *key, unsigned char *iv, unsigned char *ciphertext) {
    AES_KEY aes_key;
    AES_set_encrypt_key(key, 128, &aes_key);
    
    AES_cbc_encrypt(plaintext, ciphertext, plaintext_len, &aes_key, iv, AES_ENCRYPT);
}

// Function to decrypt using AES in CBC mode
void aes_cbc_decrypt(const unsigned char *ciphertext, int ciphertext_len, unsigned char *key, unsigned char *iv, unsigned char *plaintext) {
    AES_KEY aes_key;
    AES_set_decrypt_key(key, 128, &aes_key);
    
    AES_cbc_encrypt(ciphertext, plaintext, ciphertext_len, &aes_key, iv, AES_DECRYPT);
}

// Function to encrypt using AES in CFB mode
void aes_cfb_encrypt(const unsigned char *plaintext, int plaintext_len, unsigned char *key, unsigned char *iv, unsigned char *ciphertext) {
    AES_KEY aes_key;
    AES_set_encrypt_key(key, 128, &aes_key);
    
    int num = 0;
    AES_cfb128_encrypt(plaintext, ciphertext, plaintext_len, &aes_key, iv, &num, AES_ENCRYPT);
}

// Function to decrypt using AES in CFB mode
void aes_cfb_decrypt(const unsigned char *ciphertext, int ciphertext_len, unsigned char *key, unsigned char *iv, unsigned char *plaintext) {
    AES_KEY aes_key;
    AES_set_encrypt_key(key, 128, &aes_key);
    
    int num = 0;
    AES_cfb128_encrypt(ciphertext, plaintext, ciphertext_len, &aes_key, iv, &num, AES_DECRYPT);
}

int main() {
    unsigned char key[AES_BLOCK_SIZE] = "1234567890123456";
    unsigned char iv[AES_BLOCK_SIZE] = "abcdefghijklmnop";
    unsigned char plaintext[] = "Hello World12345678";
    unsigned char ciphertext[AES_BLOCK_SIZE];
    unsigned char decryptedtext[sizeof(plaintext)];

    int plaintext_len = strlen((char *)plaintext);

    // ECB mode
    aes_ecb_encrypt(plaintext, plaintext_len, key, ciphertext);
    printf("ECB encrypted: ");
    for (int i = 0; i < AES_BLOCK_SIZE; ++i) {
        printf("%02x", ciphertext[i]);
    }
    printf("\n");

    aes_ecb_decrypt(ciphertext, AES_BLOCK_SIZE, key, decryptedtext);
    decryptedtext[AES_BLOCK_SIZE] = '\0';
    printf("ECB decrypted: %s\n", decryptedtext);

    // CBC mode
    aes_cbc_encrypt(plaintext, plaintext_len, key, iv, ciphertext);
    printf("CBC encrypted: ");
    for (int i = 0; i < AES_BLOCK_SIZE; ++i) {
        printf("%02x", ciphertext[i]);
    }
    printf("\n");

    aes_cbc_decrypt(ciphertext, AES_BLOCK_SIZE, key, iv, decryptedtext);
    decryptedtext[AES_BLOCK_SIZE] = '\0';
    printf("CBC decrypted: %s\n", decryptedtext);

    // CFB mode
    aes_cfb_encrypt(plaintext, plaintext_len, key, iv, ciphertext);
    printf("CFB encrypted: ");
    for (int i = 0; i < AES_BLOCK_SIZE; ++i) {
        printf("%02x", ciphertext[i]);
    }
    printf("\n");

    aes_cfb_decrypt(ciphertext, AES_BLOCK_SIZE, key, iv, decryptedtext);
    decryptedtext[AES_BLOCK_SIZE] = '\0';
    printf("CFB decrypted: %s\n", decryptedtext);

return 0 ;

}
