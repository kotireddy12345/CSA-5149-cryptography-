#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <gmp.h>

// Function to encrypt a single character using RSA
void rsa_encrypt_char(mpz_t ciphertext, int plaintext_char, const mpz_t n, const mpz_t e) {
    mpz_t m;
    mpz_init(m);

    // Convert character to integer (0 to 25)
    mpz_set_ui(m, plaintext_char);

    // Encrypt: ciphertext = m^e % n
    mpz_powm(ciphertext, m, e, n);

    // Clean up
    mpz_clear(m);
}

int main() {
    // RSA parameters
    mpz_t n, e;
    mpz_init(n);
    mpz_init(e);

    // Assume n and e are initialized with large values (not shown here)

    // Plaintext message as a string
    char plaintext[] = "HELLO";

    // Initialize GMP variable for ciphertext
    mpz_t ciphertext;
    mpz_init(ciphertext);

    // Encrypt each character in the plaintext
    for (int i = 0; i < strlen(plaintext); i++) {
        // Convert character to corresponding integer (0 to 25)
        int plaintext_char = plaintext[i] - 'A';

        // Encrypt the character
        rsa_encrypt_char(ciphertext, plaintext_char, n, e);

        // Print or use ciphertext here (not shown for simplicity)
    }

    // Clean up GMP variables
    mpz_clear(n);
    mpz_clear(e);
    mpz_clear(ciphertext);

    return 0;
}

