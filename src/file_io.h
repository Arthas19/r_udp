#ifndef FILE_H
#define FILE_H

#include <stdio.h>
#include <stdlib.h>

size_t load_file(FILE *file, unsigned char **buffer);
void write_file(FILE *file, unsigned char *buffer, size_t size);

#endif
