#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <semaphore.h>

#include <time.h>
#include <netinet/in.h>

#define BUF 512


/* Global variables */
static FILE *in_file, *out_file;

static sem_t semaphore;
static pthread_mutex_t mutex;
static pthread_t h_wire, h_wireless;

static int i = 0;

int pick_interface(pcap_if_t* device);
void* wire(void *param);
void* wireless(void *param);

int main() {

	unsigned char buffer[BUF];

	pthread_mutex_init(&mutex, NULL);
	sem_init(&semaphore, 0, 0);

	pthread_create(&h_wire, NULL, wire, 0);
	pthread_create(&h_wireless, NULL, wireless, 0);

	if ((in_file = fopen("in_file.png", "rb")) == NULL ) {
		fprintf(stderr, "%s\n", "Unable to open \"in_file.png\"");
		return EXIT_FAILURE;
	}

	if ((out_file = fopen("out_file.png", "wb")) == NULL) {
		fprintf(stderr, "%s\n", "Unable to open \"out_file.png\"");
		return EXIT_FAILURE;
	}

	while ( fread(buffer, BUF, 1, in_file) ) {
		fwrite(buffer, BUF, 1, out_file);
		memset(buffer, '\0', BUF);
	}

	if (fclose(in_file) != 0) {
		fprintf(stderr, "%s\n", "Unable to close \"i_file.png\"");
		return EXIT_FAILURE;
	}

	if (fclose(out_file) != 0) {
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
	pcap_if_t* device;
	pcap_t* device_handle;

	if ( select_device(device) == -1 ) {
		printf("%s\n", "Greska wire");
		sem_post(&semaphore);

		return;
	}

	printf("SELECTED: %s\n\n", device->name);

	sem_post(&semaphore);
	sleep(1);
	sem_wait(&semaphore);
}

void* wireless(void *param) {
	pcap_if_t* device;
	pcap_t* device_handle;

	sem_wait(&semaphore);

	if ( select_device(device) == -1 ) {
		printf("%s\n", "Greska wireless");
		sem_post(&semaphore);

		return;
	}

	printf("SELECTED: %s\n\n", device->name);

	sem_post(&semaphore);

	return;
}

// This function provide possibility to chose device from the list of available devices
int select_device(pcap_if_t* device) {
	int i=0;	// Count devices and provide jumping to the selected device
	int device_num;
	pcap_if_t* devices;
	char error_buffer[BUF];

	/* Retrieve the device list on the local machine */
	if (pcap_findalldevs(&devices, error_buffer) == -1) {
		printf("Error in pcap_findalldevs: %s\n", error_buffer);
		return -1;
	}

    // Print the list
    for (device=devices; device; device=device->next) {
        printf("%d. %s", ++i, device->name);
        if (device->description)
            printf(" (%s)\n", device->description);
        else
            printf(" (No description available)\n");
    }

    if (i==0) {
        printf("\nNo interfaces found! Make sure WinPcap is installed.\n");
        return -1;
    }

	// Pick one device from the list
    printf("Enter the interface number (1-%d):", i);
    scanf("%d", &device_num);

    if(device_num < 1 || device_num > i) {
        printf("\nInterface number out of range.\n");
        return -1;
    }

     // Jump to the selected device
    for(device = devices, i = 0; i < device_num-1; device=device->next, i++);

	return 0;
}
