#include "file_io.h"

size_t load_file(FILE *file, unsigned char **buffer) {

    size_t size;

    fseek(file, 0, SEEK_END);
    size = ftell(file);
    fseek(file, 0, SEEK_SET);

    *buffer = (unsigned char*)malloc(size+1);
    fread(*buffer, 1, size, file);

    *(*buffer + size) = '\0';
    (*buffer)[size]   = '\0';
    buffer[0][size]   = '\0';

    return size;
}

void write_file(FILE *file, unsigned char *buffer, size_t size) {
    fwrite(buffer, 1, size, file);
}
