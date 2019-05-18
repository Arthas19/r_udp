#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <semaphore.h>

#include <unistd.h>

#define BUF 512


/* Global variables */
static FILE *in_file, *out_file;

static sem_t semaphore;
static pthread_mutex_t mutex;
static pthread_t h_wire, h_wireless;

static int i_packet = 0;


/* Functions used */
void* wire(void *param);
void* wireless(void *param);
pcap_if_t* select_device(pcap_if_t* devices);


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
	pcap_t* device_handle;
	pcap_if_t *device, *devices;

	unsigned char error_buffer[PCAP_ERRBUF_SIZE];

	if(pcap_findalldevs(&devices, error_buffer) == -1)
	{
		printf("Error in pcap_findalldevs: %s\n", error_buffer);
		return NULL;
	}

	printf("%s\n", "WIRE:");

	device = select_device(devices);

	if (device == NULL) {
		pcap_freealldevs(devices);
		sem_post(&semaphore);

		return NULL;
	}

	printf("SELECTED: %s\n\n", device->name);

	sem_post(&semaphore);
	sleep(1);
	sem_wait(&semaphore);

	// Open the capture device
	if ((device_handle = pcap_open_live( device->name,		// name of the device
							  65536,						// portion of the packet to capture (65536 guarantees that the whole packet will be captured on all the link layers)
							  1,							// promiscuous mode
							  500,							// read timeout
							  error_buffer					// buffer where error message is stored
							  )) == NULL)
	{
		printf("\nUnable to open the adapter. %s is not supported by libpcap/WinPcap\n", device->name);
		pcap_freealldevs(devices);

		return NULL;
	}

	pcap_freealldevs(devices);
}

void* wireless(void *param) {
	pcap_t* device_handle;
	pcap_if_t *device, *devices;

	unsigned char error_buffer[PCAP_ERRBUF_SIZE];


	sem_wait(&semaphore);

	if(pcap_findalldevs(&devices, error_buffer) == -1) {
		printf("Error in pcap_findalldevs: %s\n", error_buffer);

		return NULL;
	}

	printf("%s\n", "WIRELESS:");

	device = select_device(devices);

	if (device == NULL) {
		pcap_freealldevs(devices);
		sem_post(&semaphore);

		return NULL;
	}

	printf("SELECTED: %s\n\n", device->name);

	sem_post(&semaphore);

	// Open the capture device
	if ((device_handle = pcap_open_live( device->name,		// name of the device
							  65536,						// portion of the packet to capture (65536 guarantees that the whole packet will be captured on all the link layers)
							  1,							// promiscuous mode
							  500,							// read timeout
							  error_buffer					// buffer where error message is stored
							  )) == NULL)
	{
		printf("\nUnable to open the adapter. %s is not supported by libpcap/WinPcap\n", device->name);
		pcap_freealldevs(devices);

		return NULL;
	}

	pcap_freealldevs(devices);
}

// This function provide possibility to chose device from the list of available devices
pcap_if_t* select_device(pcap_if_t* devices) {
	int i=0;	// Count devices and provide jumping to the selected device
	int device_num;
	pcap_if_t* device;

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
        return NULL;
    }

	// Pick one device from the list
    printf("Enter the interface number (1-%d):", i);
    scanf("%d", &device_num);

    if(device_num < 1 || device_num > i) {
        printf("\nInterface number out of range.\n");
        return NULL;
    }

     // Jump to the selected device
    for(device = devices, i = 0; i < device_num-1; device=device->next, i++);

	return device;
}
