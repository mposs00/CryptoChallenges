#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "base64.h"
#include "frequency.h"
#include "data_utils.h"

int compare(const void* a, const void* b) {
    return (*(int*)a - *(int*)b);
}

void guess_line(char* str) {
    int len = strlen(str) >> 1;
    char* bytes = (char*)malloc(len);
    hex_to_bytes(str, len, bytes);
    //printf("Input data: ");
    //print_bytes(bytes, len);

    double chis[256];
    int candidates[256];
    int num_candidates = 0;;

    for (int key = 0; key <= 255; key++) {
        char* xor_out = (char*)malloc(len);
        for (int i = 0; i < len; i++) {
            xor_out[i] = bytes[i] ^ key;
        }
        chis[key] = chi2(xor_out, len);
        if (chis[key] < 50) {
            candidates[num_candidates] = key;
            num_candidates++;
            printf("Candidate key 0x%2X with Chi2 %f\n", (key & 0xFF), chis[key]);
        }
        free(xor_out);
    }

    for (int i = 0; i < num_candidates; i++) {
        int key = candidates[i];
        char* xor_out = (char*)malloc(len);
        for (int i = 0; i < len; i++) {
            xor_out[i] = bytes[i] ^ key;
        }
        printf("Decryption for candidate key 0x%2X (Chi2 %f): %s\n", (key & 0xFF), chis[key], xor_out);
        printf("Ciphertext: ");
        print_bytes(bytes, len);
        printf("-------------------------------------\n");
        free(xor_out);
    }
}

int main()
{
    FILE* fp;
    char* line = NULL;
    size_t len = 0;
    ssize_t read;

    errno_t success = fopen_s(&fp, "C:\\Users\\Marisa\\Documents\\4.txt", "r");
    if (success != 0) {
        exit(EXIT_FAILURE);
    }

    while ((read = getline(&line, &len, fp)) != -1) {
        guess_line(line);
    }

    fclose(fp);
    if (line)
        free(line);

    return 0;
}