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
    FILE* fp;
    char* line = NULL;
    size_t len = 0;
    ssize_t read;

    errno_t success = fopen_s(&fp, "C:\\Users\\Marisa\\Documents\\8.txt", "r");
    if (success != 0)
        exit(EXIT_FAILURE);

    int blocklen = 16;

    printf("Trying block size %d....\n", blocklen);
    while ((read = getline(&line, &len, fp)) != -1) {
        int len = strlen(line) >> 1;
        char* bytes = (char*)malloc(len);
        hex_to_bytes(line, len, bytes);

        int num_blocks = (len / blocklen);
        //printf("line: ");
        //print_bytes(bytes, len);
        //printf("num blocks: %d\n", num_blocks);
        char** blocks = (char**)malloc(sizeof(char*) * num_blocks);

        for (int i = 0; i < num_blocks; i++) {
            blocks[i] = (char*)malloc(blocklen);
            memcpy(blocks[i], bytes + (i * blocklen), blocklen);
            //printf("block %d ptr: 0x%x\n", i, blocks[i]);
        }

        qsort(blocks, num_blocks, sizeof(char*), compare);

        for (int i = 1; i < num_blocks; i++) {
            //printf("block %d: ", i);
            //print_bytes(blocks[i], blocklen);
            if (memcmp(blocks[i - 1], blocks[i], blocklen) == 0) {
                printf("duplicate found, likely encrypted string: ");
                print_bytes(bytes, len);
            }
        }

        for (int i = 0; i < num_blocks; i++) {
            free(blocks[i]);
        }
        free(blocks);
        free(bytes);
    }
    printf("-------------------------------------------------\n");

    fclose(fp);
    if (line)
        free(line);

    return 0;
}