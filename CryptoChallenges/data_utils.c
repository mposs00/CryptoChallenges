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