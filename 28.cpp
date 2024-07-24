#include <stdio.h>
#include <openssl/dh.h>

void handleErrors(void)
{
    printf("An error occurred\n");
    abort();
}

int main()
{
    DH *dh = NULL;
    int codes, secret_size;
    unsigned char *secret;

    // Create new Diffie-Hellman parameters
    dh = DH_new();
    if (dh == NULL) {
        handleErrors();
    }

    // Use predefined parameters for demonstration (in practice, generate these securely)
    codes = DH_generate_parameters_ex(dh, 256, DH_GENERATOR_2, NULL);
    if (codes != 1) {
        handleErrors();
    }

    // Generate public and private keys for Alice
    codes = DH_generate_key(dh);
    if (codes != 1) {
        handleErrors();
    }

    // Print Alice's public key
    printf("Alice's public key (A): %s\n", BN_bn2hex(dh->pub_key));

    // Assume Alice sends her public key to Bob securely

    // Bob receives Alice's public key and computes his own keys
    DH *dh_bob = DH_new();
    dh_bob->p = BN_dup(dh->p);
    dh_bob->g = BN_dup(dh->g);
    codes = DH_generate_key(dh_bob);
    if (codes != 1) {
        handleErrors();
    }

    // Print Bob's public key
    printf("Bob's public key (B): %s\n", BN_bn2hex(dh_bob->pub_key));

    // Alice and Bob compute the shared secret
    secret_size = DH_size(dh_bob);
    secret = (unsigned char *)malloc(secret_size);
    if (secret == NULL) {
        handleErrors();
    }

    codes = DH_compute_key(secret, dh_bob->pub_key, dh);
    if (codes < 0) {
        handleErrors();
    }

    printf("Shared secret: ");
    for (int i = 0; i < secret_size; i++) {
        printf("%02x", secret[i]);
    }
    printf("\n");

    // Clean up
    free(secret);
    DH_free(dh);
    DH_free(dh_bob);

    return 0;
}

