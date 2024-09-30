#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/md5.h>
#include <openssl/sha.h>
#include <openssl/ripemd.h>
#include <openssl/evp.h>
#include <time.h>
#include "blake2.h"
#include "blake3.h"

#define HASH_LENGTH 16

void print_hash(const char *algorithm, unsigned char *hash, size_t length) {
    printf("%s: ", algorithm);
    for (size_t i = 0; i < length; i++) {
        printf("%02x", hash[i]);
    }
    printf("\n");
}

void calculate_time(struct timespec start, struct timespec end) {
    double time_taken = (end.tv_sec - start.tv_sec) + (end.tv_nsec - start.tv_nsec) / 1e9;
    double microseconds = time_taken*1000000;
    printf("Time: %.6f microseconds\n", microseconds);
}

int main(int argc, char *argv[]) {
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <string>\n", argv[0]);
        return 1;
    }

    const char *input = argv[1];
    unsigned char md5_hash[MD5_DIGEST_LENGTH];
    unsigned char sha1_hash[SHA_DIGEST_LENGTH];
    unsigned char blake2_hash[HASH_LENGTH];
    unsigned char blake3_hash[HASH_LENGTH];
    unsigned char sha256_hash[SHA256_DIGEST_LENGTH];
    unsigned char sha512_hash[SHA512_DIGEST_LENGTH];
    unsigned char sha3_256_hash[SHA256_DIGEST_LENGTH];
    unsigned char sha3_512_hash[SHA512_DIGEST_LENGTH];
    unsigned char ripemd160_hash[RIPEMD160_DIGEST_LENGTH];
    struct timespec start, end;

    // MD5
    clock_gettime(CLOCK_MONOTONIC, &start);
    MD5((unsigned char*)input, strlen(input), md5_hash);
    clock_gettime(CLOCK_MONOTONIC, &end);
    print_hash("MD5", md5_hash, MD5_DIGEST_LENGTH);
    calculate_time(start, end);
    printf("\n");

    // SHA1
    clock_gettime(CLOCK_MONOTONIC, &start);
    SHA1((unsigned char*)input, strlen(input), sha1_hash);
    clock_gettime(CLOCK_MONOTONIC, &end);
    print_hash("SHA1", sha1_hash, SHA_DIGEST_LENGTH);
    calculate_time(start, end);
    printf("\n");

    // SHA-256 
    clock_gettime(CLOCK_MONOTONIC, &start);
    SHA256((unsigned char*)input, strlen(input), sha256_hash);
    clock_gettime(CLOCK_MONOTONIC, &end);
    print_hash("SHA-256", sha256_hash, SHA256_DIGEST_LENGTH);
    calculate_time(start, end);
    printf("\n");

    // SHA-512
    clock_gettime(CLOCK_MONOTONIC, &start);
    SHA512((unsigned char*)input, strlen(input), sha512_hash);
    clock_gettime(CLOCK_MONOTONIC, &end);
    print_hash("SHA-512", sha512_hash, SHA512_DIGEST_LENGTH);
    calculate_time(start, end);
    printf("\n");

    // SHA3-256
    clock_gettime(CLOCK_MONOTONIC, &start);
    EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(mdctx, EVP_sha3_256(), NULL);
    EVP_DigestUpdate(mdctx, input, strlen(input));
    EVP_DigestFinal_ex(mdctx, sha3_256_hash, NULL);
    EVP_MD_CTX_free(mdctx);
    clock_gettime(CLOCK_MONOTONIC, &end);
    print_hash("SHA3-256", sha3_256_hash, SHA256_DIGEST_LENGTH);
    calculate_time(start, end);
    printf("\n");

    // SHA3-512
    clock_gettime(CLOCK_MONOTONIC, &start);
    mdctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(mdctx, EVP_sha3_512(), NULL);
    EVP_DigestUpdate(mdctx, input, strlen(input));
    EVP_DigestFinal_ex(mdctx, sha3_512_hash, NULL);
    EVP_MD_CTX_free(mdctx);
    clock_gettime(CLOCK_MONOTONIC, &end);
    print_hash("SHA3-512", sha3_512_hash, SHA512_DIGEST_LENGTH);
    calculate_time(start, end);
    printf("\n");

    // RIPEMD-160
    clock_gettime(CLOCK_MONOTONIC, &start);
    RIPEMD160((unsigned char*)input, strlen(input), ripemd160_hash);
    clock_gettime(CLOCK_MONOTONIC, &end);
    print_hash("RIPEMD-160", ripemd160_hash, RIPEMD160_DIGEST_LENGTH);
    calculate_time(start, end);
    printf("\n");

    // BLAKE2b (ref)
    clock_gettime(CLOCK_MONOTONIC, &start);
    blake2refb(blake2_hash, HASH_LENGTH, input, strlen(input), NULL, 0);
    clock_gettime(CLOCK_MONOTONIC, &end);
    print_hash("BLAKE2b (ref)", blake2_hash, HASH_LENGTH);
    calculate_time(start, end);
    printf("\n");

    // BLAKE2bp (ref)
    clock_gettime(CLOCK_MONOTONIC, &start);
    blake2refbp(blake2_hash, HASH_LENGTH, input, strlen(input), NULL, 0);
    clock_gettime(CLOCK_MONOTONIC, &end);
    print_hash("BLAKE2bp (ref)", blake2_hash, HASH_LENGTH);
    calculate_time(start, end);
    printf("\n");

    // BLAKE2b (sse)
    clock_gettime(CLOCK_MONOTONIC, &start);
    blake2b(blake2_hash, HASH_LENGTH, input, strlen(input), NULL, 0);
    clock_gettime(CLOCK_MONOTONIC, &end);
    print_hash("BLAKE2b (sse)", blake2_hash, HASH_LENGTH);
    calculate_time(start, end);
    printf("\n");

    // BLAKE2bp (sse)
    clock_gettime(CLOCK_MONOTONIC, &start);
    blake2bp(blake2_hash, HASH_LENGTH, input, strlen(input), NULL, 0);
    clock_gettime(CLOCK_MONOTONIC, &end);
    print_hash("BLAKE2bp (sse)", blake2_hash, HASH_LENGTH);
    calculate_time(start, end);
    printf("\n");

    // BLAKE3
    clock_gettime(CLOCK_MONOTONIC, &start);
    struct blake3 hasher;
    blake3_init(&hasher);
    blake3_update(&hasher, input, strlen(input));
    blake3_out(&hasher, blake3_hash, HASH_LENGTH);
    clock_gettime(CLOCK_MONOTONIC, &end);
    print_hash("BLAKE3", blake3_hash, HASH_LENGTH);
    calculate_time(start, end);
    printf("\n\n");
    
    return 0;
}
