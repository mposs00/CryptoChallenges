#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/evp.h>

#include "base64.h"
#include "frequency.h"
#include "data_utils.h"

int main()
{
    char plaintext_str[] = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
    int ciphertext_len = 0;
    char* ciphertext = black_box(plaintext_str, strlen(plaintext_str), &ciphertext_len);
    print_bytes(ciphertext, ciphertext_len);
    int is_ecb = detect_ecb(ciphertext, ciphertext_len);
    if (is_ecb > 0) {
        printf("ECB is likely in use.\n");
    }
    else {
        printf("CBC is likely in use.\n");
    }

    return 0;
}