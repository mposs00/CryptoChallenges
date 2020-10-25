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
    char str[] = "YELLOW SUBMARINE";
    printf("input bytes: ");
    print_bytes(str, strlen(str));

    char* padded = pad(str, 20);
    printf("paded bytes: ");
    print_bytes(padded, 20);

    return 0;
}