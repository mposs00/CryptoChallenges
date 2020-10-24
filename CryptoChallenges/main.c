#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "base64.h"
#include "frequency.h"
#include "data_utils.h"

#define MAX_KEYSIZE 64

int guess_line(char* bytes, int len) {
    //print_bytes(bytes, len);
    double chis[256];

    for (int key = 0; key <= 255; key++) {
        char* xor_out = (char*)malloc(len);
        for (int i = 0; i < len; i++) {
            xor_out[i] = bytes[i] ^ key;
        }
        chis[key] = chi2(xor_out, len);
        //if (chis[key] < 40) {
        //    printf("xor result for key 0x%02x (chi %f): %s\n", key, chis[key], xor_out);
        //}
        free(xor_out);
    }

    double min = 100000000;
    int min_idx = 0;

    for (int i = 0; i < 256; i++) {
        if (chis[i] < min) {
            min = chis[i];
            min_idx = i;
        }
    }

    return min_idx;
}

int main()
{
    char base64_input[] = "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";
    int input_len = 0;
    char* input = unbase64(base64_input, strlen(base64_input), &input_len);
    
    /*
    // Test each part of our code before hand...
    char test_input[] = "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736";
    int test_len = strlen(test_input) >> 1;
    char* test_b = (char*)malloc(test_len);
    hex_to_bytes(test_input, test_len, test_b);
    int k = guess_line(test_b, test_len);
    char* dec = (char*)malloc(test_len);
    for (int i = 0; i < test_len; i++) {
        dec[i] = test_b[i] ^ k;
    }
    printf("0x%02x: %s\n", k, dec);
    printf("Hamming distance sanity check: %d\n", hamming_distance("this is a test", "wokka wokka!!!", 14));*/

    int candidate_sizes[MAX_KEYSIZE];
    int num_candidates = 0;
    double totals = 0;
    int num_loops = 0;
    for (int keysize = 2; keysize < MAX_KEYSIZE; keysize++) {
        int i = 0;
        while ((i * keysize) + keysize < input_len) {
            char* first_group = (char*)malloc(keysize);
            char* second_group = (char*)malloc(keysize);

            //printf("Allocating blocks for keysize %d, offsets:%d, %d\n", keysize, (i * keysize), (i * keysize) + keysize);

            memcpy(first_group, input + (i * keysize), keysize);
            memcpy(second_group, input + (i * keysize) + keysize, keysize);
            double hamdist = hamming_distance(first_group, second_group, keysize) / keysize;
            totals += hamdist;
            num_loops++;

            i += 2;

            free(first_group);
            free(second_group);
        }
        double avg = totals / num_loops;
        if (avg < 2.5) {
            candidate_sizes[num_candidates] = keysize;
            num_candidates++;
        }
        totals = 0;
        num_loops = 0;
    }

    printf("---------------------------------------------\n");

    for (int i = 0; i < num_candidates; i++) {
        int keysize = candidate_sizes[i];
        printf("Candidate keysize: %d\n", keysize);
        char* key_guess = (char*)malloc(keysize);

        // Break input into keysize-sized blocks
        int num_blocks = input_len / keysize;
        char** blocks = (char**)malloc(sizeof(char*) * num_blocks);
        for (int i = 0; i < num_blocks; i++) {
            blocks[i] = (char*)malloc(keysize);
            memcpy(blocks[i], (input + (keysize * i)), keysize);
        }

        // Allocate transposed blocks
        char** transposed_blocks = (char**)malloc(sizeof(char*) * keysize);
        for (int i = 0; i < keysize; i++) {
            transposed_blocks[i] = (char*)malloc(num_blocks);
        }

        // Do the transposition
        for (int x = 0; x < keysize; x++) {
            for (int y = 0; y < num_blocks; y++) {
                transposed_blocks[x][y] = blocks[y][x];
            }
            //printf("Transposed block with position %d\n", x);
            int guess_key = guess_line(transposed_blocks[x], num_blocks);
            //printf("Best guess for block %d: 0x%02x\n", x, guess_key);
            key_guess[x] = (guess_key & 0xFF);
            //print_bytes(transposed_blocks[x], num_blocks);
        }

        printf("Guessed key:");
        print_bytes(key_guess, keysize);
        char* plaintext = (char*)malloc(input_len);
        for (int i = 0; i < input_len; i++) {
            plaintext[i] = input[i] ^ key_guess[i % keysize];
        }
        printf("Result: %s\n", plaintext);

        // Free blocks
        for (int i = 0; i < num_blocks; i++) {
            free(blocks[i]);
        }
        free(blocks);

        for (int i = 0; i < keysize; i++) {
            free(transposed_blocks[i]);
        }
        free(transposed_blocks);
        free(key_guess);
        free(plaintext);
    }

    return 0;
}