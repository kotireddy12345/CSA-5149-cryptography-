#include <stdio.h>
#include <stdint.h>
#include <string.h>

#define KECCAK_ROUNDS 24
#define STATE_SIZE 1600 // State size in bits for SHA-3-1024

typedef struct {
    uint64_t A[5][5]; // State matrix A
    uint64_t capacity[2]; // Capacity part (512 bits)
    uint64_t rate[16]; // Rate part (1024 bits - 512 bits for capacity)
    int rate_position; // Position in the rate part
} sha3_1024_ctx;

// Rotation function
#define ROTL64(x, y) (((x) << (y)) | ((x) >> (64 - (y))))

// Keccak round constants
const uint64_t keccak_rc[24] = {
    0x0000000000000001ULL, 0x0000000000008082ULL, 0x800000000000808AULL, 0x8000000080008000ULL,
    0x000000000000808BULL, 0x0000000080000001ULL, 0x8000000080008081ULL, 0x8000000000008009ULL,
    0x000000000000008AULL, 0x0000000000000088ULL, 0x0000000080008009ULL, 0x000000008000000AULL,
    0x000000008000808BULL, 0x800000000000008BULL, 0x8000000000008089ULL, 0x8000000000008003ULL,
    0x8000000000008002ULL, 0x8000000000000080ULL, 0x000000000000800AULL, 0x800000008000000AULL,
    0x8000000080008081ULL, 0x8000000000008080ULL, 0x0000000080000001ULL, 0x8000000080008008ULL
};

// Function to initialize SHA-3 context
void sha3_1024_init(sha3_1024_ctx *ctx) {
    memset(ctx, 0, sizeof(sha3_1024_ctx));
}

// Function to absorb a single message block (1024 bits) into the state
void sha3_1024_absorb(sha3_1024_ctx *ctx, const uint64_t *block) {
    int i;

    // XOR the block into the rate part
    for (i = 0; i < 16; i++) {
        ctx->rate[i] ^= block[i];
    }

    // Perform Keccak-f[1600] permutation
    keccak_permutation(ctx->A);
}

// Keccak-f[1600] permutation function
void keccak_permutation(uint64_t A[5][5]) {
    int round, i, j, k;
    uint64_t C[5], D[5], B[5][5];

    for (round = 0; round < KECCAK_ROUNDS; round++) {
        // ? step
        for (i = 0; i < 5; i++) {
            C[i] = A[i][0] ^ A[i][1] ^ A[i][2] ^ A[i][3] ^ A[i][4];
        }
        for (i = 0; i < 5; i++) {
            D[i] = C[(i + 4) % 5] ^ ROTL64(C[(i + 1) % 5], 1);
        }
        for (i = 0; i < 5; i++) {
            for (j = 0; j < 5; j++) {
                A[i][j] ^= D[i];
            }
        }

        // ? and p steps
        for (i = 0; i < 5; i++) {
            for (j = 0; j < 5; j++) {
                B[j][(2 * i + 3 * j) % 5] = ROTL64(A[i][j], (j + 1) * (i + 1));
            }
        }

        // ? step
        for (i = 0; i < 5; i++) {
            for (j = 0; j < 5; j++) {
                A[i][j] = B[i][j] ^ ((~B[(i + 1) % 5][j]) & B[(i + 2) % 5][j]);
            }
        }

        // ? step
        A[0][0] ^= keccak_rc[round];
    }
}

// Function to finalize SHA-3 and produce the hash output
void sha3_1024_finalize(sha3_1024_ctx *ctx, uint8_t *hash) {
    // XOR the last block and padding bits into the rate part
    ctx->rate[ctx->rate_position] ^= 0x06; // Append 0x06 for SHA-3-1024
    ctx->rate[15] ^= 0x8000000000000000ULL; // Append 0x8000000000000000

    // Perform final Keccak-f[1600] permutation
    keccak_permutation(ctx->A);

    // Extract the hash output from the state matrix (capacity part)
    memcpy(hash, ctx->capacity, 64); // 64 bytes for SHA-3-1024 output
}

int main() {
    sha3_1024_ctx ctx;
    uint8_t hash[128]; // SHA-3-1024 produces 128-byte hash output (1024 bits)

    // Initialize SHA-3 context
    sha3_1024_init(&ctx);

    // Example message (1024-bit block)
    uint64_t message[16] = {
        0x0123456789ABCDEFULL, 0xFEDCBA9876543210ULL,
        0x123456789ABCDEF0ULL, 0xFEDCBA9876543210ULL,
        0x0123456789ABCDEFULL, 0xFEDCBA9876543210ULL,
        0x123456789ABCDEF0ULL, 0xFEDCBA9876543210ULL,
        0x0123456789ABCDEFULL, 0xFEDCBA9876543210ULL,
        0x123456789ABCDEF0ULL, 0xFEDCBA9876543210ULL,
        0x0123456789ABCDEFULL, 0xFEDCBA9876543210ULL,
        0x123456789ABCDEF0ULL, 0xFEDCBA9876543210ULL
    };

    // Absorb the message block
    sha3_1024_absorb(&ctx, message);

    // Finalize and get the hash output
    sha3_1024_finalize(&ctx, hash);

    // Print the hash output
    printf("SHA3-1024 Hash: ");
    for (int i = 0; i < 128; i++) {
        printf("%02x", hash[i]);
    }
    printf("\n");

    return 0;
}

