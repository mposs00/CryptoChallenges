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
		printf("%02x", (unsigned)(unsigned char)data[i]);
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

int decrypt(unsigned char* ciphertext, int ciphertext_len, unsigned char* key, unsigned char* iv, unsigned char* plaintext)
{
    EVP_CIPHER_CTX* ctx;
    
    int len, plaintext_len;
    if (!(ctx = EVP_CIPHER_CTX_new()))
        ERR_print_errors_fp(stderr);

    if (EVP_DecryptInit_ex(ctx, EVP_aes_128_ecb(), NULL, key, iv) != 1)
        ERR_print_errors_fp(stderr);

    if (EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len) != 1)
        ERR_print_errors_fp(stderr);

    plaintext_len = len;

    if (EVP_DecryptFinal_ex(ctx, plaintext + len, &len))
        ERR_print_errors_fp(stderr);
    plaintext_len += len;

    EVP_CIPHER_CTX_free(ctx);
    return plaintext_len;
}