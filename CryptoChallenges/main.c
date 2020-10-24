#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "base64.h"
#include "frequency.h"
#include "data_utils.h"

int main()
{
    char plaintext[] = "Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal";
    char key[] = "ICE";
    char* ciphertext = (char*)malloc(strlen(plaintext));

    for (int i = 0; i < strlen(plaintext); i++) {
        ciphertext[i] = plaintext[i] ^ key[i % strlen(key)];
    }

    print_bytes(ciphertext, strlen(plaintext));

    return 0;
}