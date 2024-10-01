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
#define NUM_ALGORITHMS 12

typedef struct {
    const char *name;
    double total_time;
    double avg_time;
    double min_time;
    double max_time;
} HashAlgorithm;

void print_hash(const char *algorithm, unsigned char *hash, size_t length) {
    printf("%s: ", algorithm);
    for (size_t i = 0; i < length; i++) {
        printf("%02x", hash[i]);
    }
    printf("\n");
}

double calculate_time(struct timespec start, struct timespec end) {
    return (end.tv_sec - start.tv_sec) + (end.tv_nsec - start.tv_nsec) / 1e9;
}

void print_time(const char *algorithm, double total_time, double min_time, double max_time, int iterations) {
    double microseconds = total_time * 1e6;
    double avg_microseconds = microseconds / iterations;
    double min_microseconds = min_time * 1e6;
    double max_microseconds = max_time * 1e6;
    printf("%s - Total Time: %.6f µs, Average Time: %.6f µs, Min Time: %.6f µs, Max Time: %.6f µs\n", 
           algorithm, microseconds, avg_microseconds, min_microseconds, max_microseconds);
}

int compare(const void *a, const void *b) {
    HashAlgorithm *algA = (HashAlgorithm *)a;
    HashAlgorithm *algB = (HashAlgorithm *)b;
    return (algA->avg_time > algB->avg_time) - (algA->avg_time < algB->avg_time);
}

void print_colored_summary(HashAlgorithm *algorithms, int num_algorithms) {
    const char *colors[] = {
        "\033[1;32m", // Green
        "\033[1;33m", // Yellow
        "\033[1;31m", // Red
    };
    const char *reset_color = "\033[0m";

    printf("Ranking of algorithms from fastest to slowest:\n");
    for (int i = 0; i < num_algorithms; i++) {
        const char *color;
        if (i < num_algorithms / 3) {
            color = colors[0]; // Green
        } else if (i < 2 * num_algorithms / 3) {
            color = colors[1]; // Yellow
        } else {
            color = colors[2]; // Red
        }
        printf("%s%d. %s - Average Time: %.6f µs%s\n", color, i + 1, algorithms[i].name, algorithms[i].avg_time * 1e6, reset_color);
    }
}

int main(int argc, char *argv[]) {
    if (argc < 2 || argc > 4) {
        fprintf(stderr, "Usage: %s <string> [iterations] [--summary]\n", argv[0]);
        return 1;
    }

    const char *input = argv[1];
    int iterations = 1;
    int show_summary = 0;

    if (argc >= 3) {
        if (strcmp(argv[2], "--summary") == 0) {
            show_summary = 1;
        } else {
            iterations = atoi(argv[2]);
        }
    }

    if (argc == 4 && strcmp(argv[3], "--summary") == 0) {
        show_summary = 1;
    }

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
    double total_time, min_time, max_time, current_time;

    HashAlgorithm algorithms[NUM_ALGORITHMS] = {
        {"MD5", 0.0, 0.0, 1e9, 0.0},
        {"SHA1", 0.0, 0.0, 1e9, 0.0},
        {"SHA-256", 0.0, 0.0, 1e9, 0.0},
        {"SHA-512", 0.0, 0.0, 1e9, 0.0},
        {"SHA3-256", 0.0, 0.0, 1e9, 0.0},
        {"SHA3-512", 0.0, 0.0, 1e9, 0.0},
        {"RIPEMD-160", 0.0, 0.0, 1e9, 0.0},
        {"BLAKE2b (ref)", 0.0, 0.0, 1e9, 0.0},
        {"BLAKE2bp (ref)", 0.0, 0.0, 1e9, 0.0},
        {"BLAKE2b (sse)", 0.0, 0.0, 1e9, 0.0},
        {"BLAKE2bp (sse)", 0.0, 0.0, 1e9, 0.0},
        {"BLAKE3", 0.0, 0.0, 1e9, 0.0},
    };

    // MD5
    for (int i = 0; i < iterations; i++) {
        clock_gettime(CLOCK_MONOTONIC, &start);
        MD5((unsigned char*)input, strlen(input), md5_hash);
        clock_gettime(CLOCK_MONOTONIC, &end);
        current_time = calculate_time(start, end);
        algorithms[0].total_time += current_time;
        if (current_time < algorithms[0].min_time) algorithms[0].min_time = current_time;
        if (current_time > algorithms[0].max_time) algorithms[0].max_time = current_time;
    }
    algorithms[0].avg_time = algorithms[0].total_time / iterations;
    print_hash("MD5", md5_hash, MD5_DIGEST_LENGTH);
    print_time("MD5", algorithms[0].total_time, algorithms[0].min_time, algorithms[0].max_time, iterations);
    printf("\n");

    // SHA1
    for (int i = 0; i < iterations; i++) {
        clock_gettime(CLOCK_MONOTONIC, &start);
        SHA1((unsigned char*)input, strlen(input), sha1_hash);
        clock_gettime(CLOCK_MONOTONIC, &end);
        current_time = calculate_time(start, end);
        algorithms[1].total_time += current_time;
        if (current_time < algorithms[1].min_time) algorithms[1].min_time = current_time;
        if (current_time > algorithms[1].max_time) algorithms[1].max_time = current_time;
    }
    algorithms[1].avg_time = algorithms[1].total_time / iterations;
    print_hash("SHA1", sha1_hash, SHA_DIGEST_LENGTH);
    print_time("SHA1", algorithms[1].total_time, algorithms[1].min_time, algorithms[1].max_time, iterations);
    printf("\n");

    // SHA-256 
    for (int i = 0; i < iterations; i++) {
        clock_gettime(CLOCK_MONOTONIC, &start);
        SHA256((unsigned char*)input, strlen(input), sha256_hash);
        clock_gettime(CLOCK_MONOTONIC, &end);
        current_time = calculate_time(start, end);
        algorithms[2].total_time += current_time;
        if (current_time < algorithms[2].min_time) algorithms[2].min_time = current_time;
        if (current_time > algorithms[2].max_time) algorithms[2].max_time = current_time;
    }
    algorithms[2].avg_time = algorithms[2].total_time / iterations;
    print_hash("SHA-256", sha256_hash, SHA256_DIGEST_LENGTH);
    print_time("SHA-256", algorithms[2].total_time, algorithms[2].min_time, algorithms[2].max_time, iterations);
    printf("\n");

    // SHA-512
    for (int i = 0; i < iterations; i++) {
        clock_gettime(CLOCK_MONOTONIC, &start);
        SHA512((unsigned char*)input, strlen(input), sha512_hash);
        clock_gettime(CLOCK_MONOTONIC, &end);
        current_time = calculate_time(start, end);
        algorithms[3].total_time += current_time;
        if (current_time < algorithms[3].min_time) algorithms[3].min_time = current_time;
        if (current_time > algorithms[3].max_time) algorithms[3].max_time = current_time;
    }
    algorithms[3].avg_time = algorithms[3].total_time / iterations;
    print_hash("SHA-512", sha512_hash, SHA512_DIGEST_LENGTH);
    print_time("SHA-512", algorithms[3].total_time, algorithms[3].min_time, algorithms[3].max_time, iterations);
    printf("\n");

    // SHA3-256
    for (int i = 0; i < iterations; i++) {
        clock_gettime(CLOCK_MONOTONIC, &start);
        EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
        EVP_DigestInit_ex(mdctx, EVP_sha3_256(), NULL);
        EVP_DigestUpdate(mdctx, input, strlen(input));
        EVP_DigestFinal_ex(mdctx, sha3_256_hash, NULL);
        EVP_MD_CTX_free(mdctx);
        clock_gettime(CLOCK_MONOTONIC, &end);
        current_time = calculate_time(start, end);
        algorithms[4].total_time += current_time;
        if (current_time < algorithms[4].min_time) algorithms[4].min_time = current_time;
        if (current_time > algorithms[4].max_time) algorithms[4].max_time = current_time;
    }
    algorithms[4].avg_time = algorithms[4].total_time / iterations;
    print_hash("SHA3-256", sha3_256_hash, SHA256_DIGEST_LENGTH);
    print_time("SHA3-256", algorithms[4].total_time, algorithms[4].min_time, algorithms[4].max_time, iterations);
    printf("\n");

    // SHA3-512
    for (int i = 0; i < iterations; i++) {
        clock_gettime(CLOCK_MONOTONIC, &start);
        EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
        EVP_DigestInit_ex(mdctx, EVP_sha3_512(), NULL);
        EVP_DigestUpdate(mdctx, input, strlen(input));
        EVP_DigestFinal_ex(mdctx, sha3_512_hash, NULL);
        EVP_MD_CTX_free(mdctx);
        clock_gettime(CLOCK_MONOTONIC, &end);
        current_time = calculate_time(start, end);
        algorithms[5].total_time += current_time;
        if (current_time < algorithms[5].min_time) algorithms[5].min_time = current_time;
        if (current_time > algorithms[5].max_time) algorithms[5].max_time = current_time;
    }
    algorithms[5].avg_time = algorithms[5].total_time / iterations;
    print_hash("SHA3-512", sha3_512_hash, SHA512_DIGEST_LENGTH);
    print_time("SHA3-512", algorithms[5].total_time, algorithms[5].min_time, algorithms[5].max_time, iterations);
    printf("\n");

    // RIPEMD-160
    for (int i = 0; i < iterations; i++) {
        clock_gettime(CLOCK_MONOTONIC, &start);
        RIPEMD160((unsigned char*)input, strlen(input), ripemd160_hash);
        clock_gettime(CLOCK_MONOTONIC, &end);
        current_time = calculate_time(start, end);
        algorithms[6].total_time += current_time;
        if (current_time < algorithms[6].min_time) algorithms[6].min_time = current_time;
        if (current_time > algorithms[6].max_time) algorithms[6].max_time = current_time;
    }
    algorithms[6].avg_time = algorithms[6].total_time / iterations;
    print_hash("RIPEMD-160", ripemd160_hash, RIPEMD160_DIGEST_LENGTH);
    print_time("RIPEMD-160", algorithms[6].total_time, algorithms[6].min_time, algorithms[6].max_time, iterations);
    printf("\n");

    // BLAKE2b (ref)
    for (int i = 0; i < iterations; i++) {
        clock_gettime(CLOCK_MONOTONIC, &start);
        blake2refb(blake2_hash, HASH_LENGTH, input, strlen(input), NULL, 0);
        clock_gettime(CLOCK_MONOTONIC, &end);
        current_time = calculate_time(start, end);
        algorithms[7].total_time += current_time;
        if (current_time < algorithms[7].min_time) algorithms[7].min_time = current_time;
        if (current_time > algorithms[7].max_time) algorithms[7].max_time = current_time;
    }
    algorithms[7].avg_time = algorithms[7].total_time / iterations;
    print_hash("BLAKE2b (ref)", blake2_hash, HASH_LENGTH);
    print_time("BLAKE2b (ref)", algorithms[7].total_time, algorithms[7].min_time, algorithms[7].max_time, iterations);
    printf("\n");

    // BLAKE2bp (ref)
    for (int i = 0; i < iterations; i++) {
        clock_gettime(CLOCK_MONOTONIC, &start);
        blake2refbp(blake2_hash, HASH_LENGTH, input, strlen(input), NULL, 0);
        clock_gettime(CLOCK_MONOTONIC, &end);
        current_time = calculate_time(start, end);
        algorithms[8].total_time += current_time;
        if (current_time < algorithms[8].min_time) algorithms[8].min_time = current_time;
        if (current_time > algorithms[8].max_time) algorithms[8].max_time = current_time;
    }
    algorithms[8].avg_time = algorithms[8].total_time / iterations;
    print_hash("BLAKE2bp (ref)", blake2_hash, HASH_LENGTH);
    print_time("BLAKE2bp (ref)", algorithms[8].total_time, algorithms[8].min_time, algorithms[8].max_time, iterations);
    printf("\n");

    // BLAKE2b (sse)
    for (int i = 0; i < iterations; i++) {
        clock_gettime(CLOCK_MONOTONIC, &start);
        blake2b(blake2_hash, HASH_LENGTH, input, strlen(input), NULL, 0);
        clock_gettime(CLOCK_MONOTONIC, &end);
        current_time = calculate_time(start, end);
        algorithms[9].total_time += current_time;
        if (current_time < algorithms[9].min_time) algorithms[9].min_time = current_time;
        if (current_time > algorithms[9].max_time) algorithms[9].max_time = current_time;
    }
    algorithms[9].avg_time = algorithms[9].total_time / iterations;
    print_hash("BLAKE2b (sse)", blake2_hash, HASH_LENGTH);
    print_time("BLAKE2b (sse)", algorithms[9].total_time, algorithms[9].min_time, algorithms[9].max_time, iterations);
    printf("\n");

    // BLAKE2bp (sse)
    for (int i = 0; i < iterations; i++) {
        clock_gettime(CLOCK_MONOTONIC, &start);
        blake2bp(blake2_hash, HASH_LENGTH, input, strlen(input), NULL, 0);
        clock_gettime(CLOCK_MONOTONIC, &end);
        current_time = calculate_time(start, end);
        algorithms[10].total_time += current_time;
        if (current_time < algorithms[10].min_time) algorithms[10].min_time = current_time;
        if (current_time > algorithms[10].max_time) algorithms[10].max_time = current_time;
    }
    algorithms[10].avg_time = algorithms[10].total_time / iterations;
    print_hash("BLAKE2bp (sse)", blake2_hash, HASH_LENGTH);
    print_time("BLAKE2bp (sse)", algorithms[10].total_time, algorithms[10].min_time, algorithms[10].max_time, iterations);
    printf("\n");

    // BLAKE3
    for (int i = 0; i < iterations; i++) {
        clock_gettime(CLOCK_MONOTONIC, &start);
        struct blake3 hasher;
        blake3_init(&hasher);
        blake3_update(&hasher, input, strlen(input));
        blake3_out(&hasher, blake3_hash, HASH_LENGTH);
        clock_gettime(CLOCK_MONOTONIC, &end);
        current_time = calculate_time(start, end);
        algorithms[11].total_time += current_time;
        if (current_time < algorithms[11].min_time) algorithms[11].min_time = current_time;
        if (current_time > algorithms[11].max_time) algorithms[11].max_time = current_time;
    }
    algorithms[11].avg_time = algorithms[11].total_time / iterations;
    print_hash("BLAKE3", blake3_hash, HASH_LENGTH);
    print_time("BLAKE3", algorithms[11].total_time, algorithms[11].min_time, algorithms[11].max_time, iterations);
    printf("\n");

    if (show_summary) {
        // Sorting algorithms by average time
        qsort(algorithms, NUM_ALGORITHMS, sizeof(HashAlgorithm), compare);

        // Printing ranking with colors
        print_colored_summary(algorithms, NUM_ALGORITHMS);
    }
    return 0;
    }
