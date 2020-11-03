#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/evp.h>

#include "frequency.h"
#include "data_utils.h"

int main()
{
    char* key = malloc(16);
    rand_bytes(key, 16);

    // Detect block size
    int block_size = 1;
    int last_len = 0;
    for (int i = 1; i < 32; i++) {
        char* data = malloc(i);
        int result_len = 0;
        char* result = black_box(data, i, &result_len, key);
        free(result);

        if (i == 1)
            last_len = result_len;

        if (result_len != last_len) {
            block_size = result_len - last_len;
            break;
        }
    }
    printf("block size: %d bytes\n", block_size);

    // Detect ECB
    char test_payload[] = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
    int result_len = 0;
    char* result = black_box(test_payload, strlen(test_payload), &result_len, key);
    if (detect_ecb(result, result_len) > 0)
        printf("ECB detected\n");
    else
        printf("CBC detected");

    return 0;
}