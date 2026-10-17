#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <ctype.h>
#include <openssl/bn.h>
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/sha.h>

struct challenge_state {
    char hash[64];
    uint64_t counter;
};

void openssl_fail(char *what) {
    fprintf(stderr, "%s failed\n", what);
    ERR_print_errors_fp(stderr);
    exit(EXIT_FAILURE);
}

void print_bn(char *name, BIGNUM *x)
{
    char *s = BN_bn2hex(x);

    if (s == NULL) {
        openssl_fail("BN_bn2hex");
    }

    printf("%s = 0x%s\n", name, s);
    OPENSSL_free(s);
}

void generate_r(BIGNUM *r, BIGNUM *q, unsigned char nonce_key[32], uint64_t counter, BN_CTX *ctx) {
    unsigned char blob[40];
    unsigned char digest[SHA512_DIGEST_LENGTH];

    memcpy(blob, nonce_key, 32);
    memcpy(blob + 32, &counter, sizeof(counter));

    if (SHA512(blob, sizeof(blob), digest) == NULL) {
        openssl_fail("SHA512");
    }

    if (BN_bin2bn(digest, sizeof(digest), r) == NULL) {
        openssl_fail("BN_bin2bn(r)");
    }

    if (!BN_mod(r, r, q, ctx)) {
        openssl_fail("BN_mod(r)");
    }

    if (BN_is_zero(r)) {
        if (!BN_one(r)) {
            openssl_fail("BN_one(r)");
        }
    }

    OPENSSL_cleanse(blob, sizeof(blob));
    OPENSSL_cleanse(digest, sizeof(digest));
}

int is_valid_hash(char *hash)
{
    char *p = hash;
    int pair = 0;

    for (; *p; p++) {
        if (!isxdigit((unsigned char)*p)) {
            return 0;
        }
    }

    for (p = hash; *p && *(p + 1); p += 2, pair++) {
        if (pair > 16 && !(p[0] == '0' && p[1] == '0')) {
            return 0;
        }
    }

    return 1;
}

/*
int sha256_hex(void *data, size_t len, char out[64])
{
    unsigned char digest[EVP_MAX_MD_SIZE];
    unsigned int digest_len;

    if (EVP_Digest(data, len, digest, &digest_len, EVP_sha256(), NULL) != 1)
        return 0;

    for (unsigned int i = 0; i < digest_len; i++)
        sprintf(out + (i * 2), "%02x", digest[i]);

    return 1;
}
*/

int md5_hex(void *data, size_t len, char out[32])
{
    unsigned char digest[EVP_MAX_MD_SIZE];
    unsigned int digest_len;

    if (EVP_Digest(data, len, digest, &digest_len, EVP_md5(), NULL) != 1)
        return 0;

    for (unsigned int i = 0; i < digest_len; i++)
        sprintf(out + (i * 2), "%02x", digest[i]);

    return 1;
}

int main(void)
{
    BN_CTX *ctx = BN_CTX_new();
    BIGNUM *p = NULL;
    BIGNUM *q = NULL;
    BIGNUM *g = BN_new();
    BIGNUM *secret = BN_new();
    BIGNUM *h = BN_new();
    BIGNUM *r = BN_new();
    BIGNUM *a = BN_new();
    BIGNUM *e = BN_new();
    BIGNUM *z = BN_new();
    BIGNUM *tmp = BN_new();
    unsigned char nonce_key[32];
    char expected_hash[64];
    struct challenge_state state;

    if (!ctx || !g || !secret || !h || !r || !a || !e || !z || !tmp) {
        openssl_fail("allocation");
    }

    if (!BN_hex2bn(&p, "1ed344181da88cae8dc37a08feae447ba3da7f788d271953299e5f093df7aaca987c9f653ed7e43bad576cc5d22290f61f32680736be4144642f8bea6f5bf55ef")) {
        openssl_fail("BN_hex2bn(p)");
    }

    if (!BN_hex2bn(&q, "f69a20c0ed4465746e1bd047f57223dd1ed3fbc46938ca994cf2f849efbd5654c3e4fb29f6bf21dd6abb662e911487b0f9934039b5f20a23217c5f537adfaaf7")) {
        openssl_fail("BN_hex2bn(q)");
    }

    if (!BN_set_word(g, 2)) {
        openssl_fail("BN_set_word");
    }

    do {
        if (!BN_priv_rand_range(secret, q)) {
            openssl_fail("BN_priv_rand_range(secret)");
        }
    } while (BN_is_zero(secret));

    if (!BN_mod_exp(h, g, secret, p, ctx)) {
        openssl_fail("BN_mod_exp(h)");
    }

    if (RAND_priv_bytes(nonce_key, sizeof(nonce_key)) != 1) {
        openssl_fail("RAND_priv_bytes(nonce_key)");
    }

    memset(&expected_hash, 0, sizeof(expected_hash));
    memset(&state, 0, sizeof(state));
    state.counter = 0x1337UL;
    
    int secret_len = BN_num_bytes(secret);
    unsigned char *secret_bytes = malloc(secret_len);
    if (!secret_bytes) {
        puts("malloc error.");
        return 1;
    }
    
    BN_bn2bin(secret, secret_bytes);
    // if (!sha256_hex(secret_bytes, secret_len, expected_hash))
    if (!md5_hex(secret_bytes, secret_len, expected_hash)) {
        //puts("sha256_hex error.");
        puts("md5_hex error.");    
        return 1;
    }

    free(secret_bytes);

    printf(" _________________________________________\n/ I have a secret. I'll give you the flag \\\n\\ if you know it!                         /\n -----------------------------------------\n        \\   ^__^\n         \\  (oo)\\_______\n            (__)\\       )\\/\\\n                ||----w |\n                ||     ||\n");

    while (1) {
        char input[64];
        puts("\nGenerating a new certificate!\n");
        
        generate_r(r, q, nonce_key, state.counter, ctx);
        state.counter++;

        if (!BN_mod_exp(a, g, r, p, ctx)) {
            openssl_fail("BN_mod_exp(a)");
        }

        if (!BN_priv_rand_range(e, q)) {
            openssl_fail("BN_priv_rand_range(e)");
        }

        if (!BN_mod_mul(tmp, e, secret, q, ctx)) {
            openssl_fail("BN_mod_mul(e * secret)");
        }

        if (!BN_mod_add(z, r, tmp, q, ctx)) {
            openssl_fail("BN_mod_add(z)");
        }

        puts("certificate:");
        print_bn("a", a);
        print_bn("e", e);
        print_bn("z", z);
        printf("\nhex(md5(secret)) --> ");
        //printf("\nhex(sha256(secret)) --> ");
        fflush(stdout);

        if (scanf("%64s", input) != 1) {
            puts("\ninput error.");
            break;
        }

        if (!is_valid_hash(input)) {
            puts("\ninvalid hash.");
            continue;
        }

        strcpy(state.hash, input);

        if (memcmp(state.hash, expected_hash, 32) == 0) {
            puts("\nCorrect.");

            char flag[100];
            FILE* fptr = fopen("flag.txt", "r");
            
            if (fptr == NULL) {
                printf("Failed to open flag.txt: make a ticket.\n");
            } else {
                while (fgets(flag, 100, fptr) != NULL) {
                    printf("%s", flag);
                }

                fclose(fptr);
            }

            break;
        }

        puts("\nWrong.");
    }

    return 0;
}
