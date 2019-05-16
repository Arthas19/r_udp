#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <semaphore.h>

#include <time.h>
#include <netinet/in.h>

#define BUF 512

static pthread_t h_wire, h_wireless;
static pthread_mutex_t mutex;
static sem_t semaphore;

static FILE *i_file, *o_file;

void* wire(void *param);
void* wireless(void *param);

int main() {

	unsigned char buffer[BUF];

	pthread_mutex_init(&mutex, NULL);
	sem_init(&semaphore, 0, 0);

	pthread_create(&h_wire, NULL, wire, 0);
	pthread_create(&h_wireless, NULL, wireless, 0);

	if ((i_file = fopen("in_file.png", "rb")) == NULL ) {
		fprintf(stderr, "%s\n", "Unable to open \"in_file.png\"");
		return EXIT_FAILURE;
	}

	if ((o_file = fopen("out_file.png", "wb")) == NULL) {
		fprintf(stderr, "%s\n", "Unable to open \"out_file.png\"");
		return EXIT_FAILURE;
	}

	while ( fread(buffer, BUF, 1, i_file) ) {
		fwrite(buffer, BUF, 1, o_file);
		memset(buffer, '\0', BUF);
	}

	if (fclose(i_file) != 0) {
		fprintf(stderr, "%s\n", "Unable to close \"i_file.png\"");
		return EXIT_FAILURE;
	}

	if (fclose(o_file) != 0) {
		fprintf(stderr, "%s\n", "Unable to close \"o_file.png\"");
		return EXIT_FAILURE;
	}

	pthread_join(h_wire, NULL);
	pthread_join(h_wireless, NULL);

	pthread_mutex_destroy(&mutex);
	sem_destroy(&semaphore);

	return EXIT_SUCCESS;
}

void* wire(void *param) {
	sem_post(&semaphore);
	printf("%s ", "Hello");
}

void* wireless(void *param) {
	sem_wait(&semaphore);
	printf("%s\n", "World");
}
