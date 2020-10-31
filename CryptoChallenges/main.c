#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/evp.h>

#include "base64.h"
#include "frequency.h"
#include "data_utils.h"

#define BLEN 16

int compare(void* a, void* b) {
    char* buf1 = *(char**)a;
    char* buf2 = *(char**)b;
    return memcmp(buf1, buf2, BLEN);
}

int main()
{
    char plaintext_str[] = "This is a test string to encrypt with epic CBC mode poggers";
    char key[] = "YELLOW SUBMARINE";
    char iv[16] = { 0, 1, 2, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15 };
    int plaintext_len = strlen(plaintext_str);
    int ciphertext_len = 0;
    char* ciphertext = NULL;

    aes_enc_cbc(plaintext_str, &ciphertext, key, iv, plaintext_len, &ciphertext_len);
    printf("encryption result: ");
    print_bytes(ciphertext, ciphertext_len);

    char* pt_result = malloc(ciphertext_len);
    aes_dec_cbc(pt_result, ciphertext, key, iv, ciphertext_len);
    printf("decryption result: ");
    print_bytes(pt_result, ciphertext_len);

    return 0;
}