#ifndef DATA_UTILS_H
#define DATA_UTILS_H
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <stdint.h>
#include <string.h>
#include <intrin.h>

#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>

typedef intptr_t ssize_t;

void hex_to_bytes(char hex_string[], int len, char* buf);
void print_bytes(char* data, int len);
ssize_t getline(char** lineptr, size_t* n, FILE* stream);
int _min(int a, int b);
int hamming_distance(char* str1, char* str2, int len);
char* pad(char* str, int len);
void aes_enc_block(unsigned char* plaintext, unsigned char* ciphertext, unsigned char* key);
void aes_dec_block(unsigned char* plaintext, unsigned char* ciphertext, unsigned char* key);
void aes_dec_cbc(unsigned char* plaintext, unsigned char* ciphertext, unsigned char* key, unsigned char* iv, int plaintext_len);
void aes_enc_cbc(unsigned char* plaintext, unsigned char* ciphertext, unsigned char* key, unsigned char* iv, int plaintext_len, int* ciphertext_len_out);

#endif DATA_UTILS_H