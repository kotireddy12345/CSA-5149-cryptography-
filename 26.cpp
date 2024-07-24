#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <gmp.h>

// Function to generate RSA key pair
void generate_rsa_keypair(mpz_t n, mpz_t e, mpz_t d, mpz_t p, mpz_t q) {
    mpz_t phi_n, gcd;
    gmp_randstate_t state;

    // Initialize GMP variables
    mpz_init(phi_n);
    mpz_init(gcd);
    gmp_randinit_default(state);

    // Choose random prime numbers p and q
    mpz_urandomb(p, state, 512); // 512-bit prime for demonstration
    mpz_urandomb(q, state, 512); // 512-bit prime for demonstration

    // Calculate n = p * q
    mpz_mul(n, p, q);

    // Calculate phi(n) = (p-1)*(q-1)
    mpz_sub_ui(p, p, 1); // p = p - 1
    mpz_sub_ui(q, q, 1); // q = q - 1
    mpz_mul(phi_n, p, q);

    // Choose a public exponent e (usually a small prime)
    mpz_set_ui(e, 65537); // Using 65537 (2^16 + 1) as e for demonstration

    // Compute d such that e * d = 1 (mod phi(n))
    mpz_invert(d, e, phi_n);

    // Clean up
    mpz_clear(phi_n);
    mpz_clear(gcd);
    gmp_randclear(state);
}

// Function to encrypt message m with RSA public key (n, e)
void rsa_encrypt(mpz_t ciphertext, const char *plaintext, const mpz_t n, const mpz_t e) {
    mpz_t m;
    mpz_init(m);

    // Convert plaintext to a GMP integer
    mpz_set_str(m, plaintext, 10); // Convert plaintext to mpz_t (base 10)

    // Encrypt: ciphertext = m^e % n
    mpz_powm(ciphertext, m, e, n);

    // Clean up
    mpz_clear(m);
}

// Function to decrypt ciphertext with RSA private key (n, d)
void rsa_decrypt(char *plaintext, const mpz_t ciphertext, const mpz_t n, const mpz_t d) {
    mpz_t decrypted;
    mpz_init(decrypted);

    // Decrypt: decrypted = ciphertext^d % n
    mpz_powm(decrypted, ciphertext, d, n);

    // Convert decrypted result back to string
    mpz_get_str(plaintext, 10, decrypted);

    // Clean up
    mpz_clear(decrypted);
}

int main() {
    // Declare variables
    mpz_t n, e, d, p, q, ciphertext;
    char plaintext[1024] = "Hello, RSA!"; // Plain text message to encrypt

    // Initialize GMP variables
    mpz_init(n);
    mpz_init(e);
    mpz_init(d);
    mpz_init(p);
    mpz_init(q);
    mpz_init(ciphertext);

    // Generate RSA key pair
    generate_rsa_keypair(n, e, d, p, q);

    // Encrypt the plaintext message
    rsa_encrypt(ciphertext, plaintext, n, e);

    // Print the ciphertext (as a large integer)
    gmp_printf("Ciphertext (as a large integer): %Zd\n", ciphertext);

    // Decrypt the ciphertext
    char decrypted_plaintext[1024];
    rsa_decrypt(decrypted_plaintext, ciphertext, n, d);

    // Print the decrypted plaintext
    printf("Decrypted plaintext: %s\n", decrypted_plaintext);

    // Clean up
    mpz_clear(n);
    mpz_clear(e);
    mpz_clear(d);
    mpz_clear(p);
    mpz_clear(q);
    mpz_clear(ciphertext);

    return 0;
}

