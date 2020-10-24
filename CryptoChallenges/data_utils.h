#ifndef DATA_UTILS_H
#define DATA_UTILS_H
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <stdint.h>

typedef intptr_t ssize_t;

void hex_to_bytes(char hex_string[], int len, char* buf);
void print_bytes(char* data, int len);
ssize_t getline(char** lineptr, size_t* n, FILE* stream);

#endif DATA_UTILS_H