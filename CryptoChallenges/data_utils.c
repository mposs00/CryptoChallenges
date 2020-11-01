#include "data_utils.h"

// Hex string, length of the resulting byte array, output buffer pointer
void hex_to_bytes(char hex_string[], int len, char* buf) {
	for (int i = 0; i < len; i++) {
		char substr[3];
		memcpy(substr, &hex_string[i * 2], sizeof(substr));
		substr[2] = '\0';
		buf[i] = (char) (strtol(substr, NULL, 16) & 0xFF);
	}

	return buf;
}

void print_bytes(char* data, int len) {
	for (int i = 0; i < len; i++) {
        if (i % 16 == 0 && i > 0)
            printf("\n");
		printf("%02x ", (unsigned)(unsigned char)data[i]);
	}
	printf("\n");
}

ssize_t getline(char** lineptr, size_t* n, FILE* stream) {
    size_t pos;
    int c;

    if (lineptr == NULL || stream == NULL || n == NULL) {
        errno = EINVAL;
        return -1;
    }

    c = getc(stream);
    if (c == EOF) {
        return -1;
    }

    if (*lineptr == NULL) {
        *lineptr = malloc(128);
        if (*lineptr == NULL) {
            return -1;
        }
        *n = 128;
    }

    pos = 0;
    while (c != EOF) {
        if (pos + 1 >= *n) {
            size_t new_size = *n + (*n >> 2);
            if (new_size < 128) {
                new_size = 128;
            }
            char* new_ptr = realloc(*lineptr, new_size);
            if (new_ptr == NULL) {
                return -1;
            }
            *n = new_size;
            *lineptr = new_ptr;
        }

        ((unsigned char*)(*lineptr))[pos++] = c;
        if (c == '\n') {
            break;
        }
        c = getc(stream);
    }

    (*lineptr)[pos] = '\0';
    return pos;
}

// BE CAREFUL!
// Chance of buffer overruns here. Ensure buf1 and buf2 are equal length...
int hamming_distance(char* buf1, char* buf2, int len) {
    int total = 0;

    for (int i = 0; i < len; i++) {
        int diff_bits = buf1[i] ^ buf2[i];
        total += __popcnt(diff_bits);
    }

    return total;
}

int _min(int a, int b) {
    if (a < b)
        return a;
    else return b;
}

void aes_dec_block(unsigned char* plaintext, unsigned char* ciphertext, unsigned char* key) {
    EVP_CIPHER_CTX* ctx;
    int len = 0;

    if (!(ctx = EVP_CIPHER_CTX_new()))
        ERR_print_errors_fp(stderr);

    EVP_CIPHER_CTX_set_padding(ctx, 0);

    if (1 != EVP_DecryptInit_ex(ctx, EVP_aes_128_ecb(), NULL, key, NULL))
        ERR_print_errors_fp(stderr);

    if (1 != EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, 16))
        ERR_print_errors_fp(stderr);

    EVP_CIPHER_CTX_free(ctx);
}

void aes_enc_block(unsigned char* plaintext, unsigned char* ciphertext, unsigned char* key) {
    EVP_CIPHER_CTX* ctx;
    int len = 0;

    if (!(ctx = EVP_CIPHER_CTX_new()))
        ERR_print_errors_fp(stderr);

    EVP_CIPHER_CTX_set_padding(ctx, 0);

    if (1 != EVP_EncryptInit_ex(ctx, EVP_aes_128_ecb(), NULL, key, NULL))
        ERR_print_errors_fp(stderr);

    if (1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, 16))
        ERR_print_errors_fp(stderr);

    EVP_CIPHER_CTX_free(ctx);
}

void aes_enc_cbc(unsigned char* plaintext, unsigned char** ciphertext, unsigned char* key, unsigned char* iv, int plaintext_len, int* ciphertext_len_out) {
    // Break the plaintext up into blocks
    int num_blocks = plaintext_len / 16;
    if (plaintext_len % 16 != 0)
        num_blocks++;

    *ciphertext = malloc(num_blocks * 16);
    *ciphertext_len_out = num_blocks * 16;

    // Allocate blocks
    char** blocks = malloc(num_blocks * sizeof(char*));
    for (int i = 0; i < num_blocks; i++) {
        blocks[i] = malloc(16);
        if (i == num_blocks - 1 && plaintext_len % 16 != 0) {
            char* unpadded_block = malloc(plaintext_len % 16);
            memcpy(unpadded_block, plaintext + (i * 16), plaintext_len % 16);
            char* padded_block = pad(unpadded_block, 16, plaintext_len % 16);
            memcpy(blocks[i], padded_block, 16);
            free(unpadded_block);
            free(padded_block);
        }
        else {
            memcpy(blocks[i], plaintext + (i * 16), 16);
        }
    }

    // Encrypt blocks
    char* last_block = malloc(16);
    memcpy(last_block, iv, 16);
    for (int i = 0; i < num_blocks; i++) {
        char* block_ct = malloc(16);
        // XOR plaintext
        for (int y = 0; y < 16; y++) {
            blocks[i][y] = blocks[i][y] ^ last_block[y];
        }

        aes_enc_block(blocks[i], block_ct, key);
        memcpy(last_block, block_ct, 16);
        memcpy(*ciphertext + (i * 16), block_ct, 16);

        free(block_ct);
    }

    // Free blocks
    for (int i = 0; i < num_blocks; i++) {
        free(blocks[i]);
    }
    free(blocks);
}

void aes_dec_cbc(unsigned char* plaintext, unsigned char* ciphertext, unsigned char* key, unsigned char* iv, int ciphertext_len) {
    // Break the ciphertext up into blocks
    int num_blocks = ciphertext_len / 16;

    // Allocate blocks
    char** blocks = malloc(num_blocks * sizeof(char*));
    for (int i = 0; i < num_blocks; i++) {
        blocks[i] = malloc(16);
        memcpy(blocks[i], ciphertext + (i * 16), 16);
    }

    // Encrypt blocks
    char* last_block = malloc(16);
    memcpy(last_block, iv, 16);
    for (int i = 0; i < num_blocks; i++) {
        char* block_pt = malloc(16);
        aes_dec_block(block_pt, blocks[i], key);
        // XOR plaintext
        for (int y = 0; y < 16; y++) {
            block_pt[y] = block_pt[y] ^ last_block[y];
        }
        // Update last block value
        memcpy(last_block, blocks[i], 16);
        // Update plaintext
        memcpy(plaintext + (i * 16), block_pt, 16);

        free(block_pt);
    }

    // Free blocks
    for (int i = 0; i < num_blocks; i++) {
        free(blocks[i]);
    }
    free(last_block);
    free(blocks);
}

char* pad(char* str, int len, int inlen) {
    char* padded = (char*)malloc(len);
    int pad_val = (len - inlen);
    memcpy(padded, str, inlen);
    for (int i = inlen; i < len; i++) {
        padded[i] = (char)(pad_val & 0xFF);
    }

    return padded;
}

int compare(void* a, void* b) {
    char* buf1 = *(char**)a;
    char* buf2 = *(char**)b;
    return memcmp(buf1, buf2, 16);
}

// For challenge 11.
// This function randomly encrypts some data with CBC or ECB
// Some of the data can be controlled by the "attacker"
char* black_box(char* str, int len, int* out_len) {
    srand((unsigned int) time(NULL));
    int prepend_size, append_size;
    prepend_size = (rand() % 5) + 5;
    append_size = (rand() % 5) + 5;
    char* append_bytes = malloc(append_size);
    char* prepend_bytes = malloc(prepend_size);
    rand_bytes(append_bytes, append_size);
    rand_bytes(prepend_bytes, prepend_size);

    int total_len = prepend_size + len + append_size;
    char* all_bytes = malloc(total_len);
    memcpy(all_bytes, prepend_bytes, prepend_size);
    memcpy(all_bytes + prepend_size, str, len);
    memcpy(all_bytes + prepend_size + len, append_bytes, append_size);

    free(prepend_bytes);
    free(append_bytes);

    char* ciphertext = malloc(total_len);
    char* key = malloc(16);
    char* iv = malloc(16);
    rand_bytes(key, 16);
    rand_bytes(iv, 16);
    int ct_len = 0;

    int use_ecb = rand() % 2;
    if (use_ecb == 0) {
        // I should have made this more abstract and put it in a function
        // But oh well...
        // This can also be done with just pointer manipulation
        // Although, the padding probably still needs a memcpy
        int num_blocks = total_len / 16;
        if (total_len % 16 != 0)
            num_blocks++;

        char** blocks = malloc(num_blocks * sizeof(char*));
        for (int i = 0; i < num_blocks; i++) {
            blocks[i] = malloc(16);
            if (i == num_blocks - 1 && total_len % 16 != 0) {
                char* unpadded_block = malloc(total_len % 16);
                memcpy(unpadded_block, all_bytes + (i * 16), total_len % 16);
                char* padded_block = pad(unpadded_block, 16, total_len % 16);
                memcpy(blocks[i], padded_block, 16);
                free(unpadded_block);
                free(padded_block);
            }
            else {
                memcpy(blocks[i], all_bytes + (i * 16), 16);
            }

            aes_enc_block(blocks[i], ciphertext + (i * 16), key);
            free(blocks[i]);
        }
        free(blocks);
        ct_len = num_blocks * 16;
    }
    else {
        aes_enc_cbc(all_bytes, &ciphertext, key, iv, total_len, &ct_len);
    }

    free(key);
    free(iv);
    *out_len = ct_len;
    return ciphertext;
}

int detect_ecb(char* data, int len) {
    int num_blocks = len / 16;
    char** blocks = (char**)malloc(sizeof(char*) * num_blocks);

    for (int i = 0; i < num_blocks; i++) {
        blocks[i] = (char*)malloc(16);
        memcpy(blocks[i], data + (i * 16), 16);
    }

    qsort(blocks, num_blocks, sizeof(char*), compare);

    int duplicates = 0;

    for (int i = 1; i < num_blocks; i++) {
        if (memcmp(blocks[i - 1], blocks[i], 16) == 0) {
            duplicates++;
        }
    }

    for (int i = 0; i < num_blocks; i++) {
        free(blocks[i]);
    }
    free(blocks);

    return duplicates;
}

void rand_bytes(char* buf, int len) {
    for (int i = 0; i < len; i++) {
        buf[i] = rand() & 0xFF;
    }
}