#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <pcap.h>
#include <unistd.h>
#include <pthread.h>
#include <semaphore.h>

#include "file_io.c"
#include "protocol_headers.c"

#define BUF 512

/* Global variables */
static FILE *in_file, *out_file;
static unsigned char *buffer;
static size_t size;

static sem_t semaphore;
static pthread_mutex_t mutex;
static pthread_t h_wire, h_wireless;

static int i_packet = 0;

/* Protocol based global variables */
static ethernet_header eh_eth, eh_wlan;
static ip_header ih_eth, ih_wlan;


/* Functions used */
void* wire(void *param);
void* wireless(void *param);
pcap_if_t* select_device(pcap_if_t* devices);


int main() {

	pthread_mutex_init(&mutex, NULL);
	sem_init(&semaphore, 0, 0);

	//pthread_create(&h_wire, NULL, wire, 0);
	//pthread_create(&h_wireless, NULL, wireless, 0);

	unsigned char eth_mac_src_addr[6]  = { 0x70, 0x85, 0xc2, 0x65, 0xe5, 0x25 };
	unsigned char eth_mac_dst_addr[6]  = { 0xb8, 0x27, 0xeb, 0x73, 0x1e, 0xb2 };
	unsigned char wlan_mac_src_addr[6] = { 0xec, 0x08, 0x6b, 0x08, 0x52, 0x19 };
	unsigned char wlan_mac_dst_addr[6] = { 0x00, 0x0f, 0x60, 0x04, 0x5d, 0xca };

	unsigned char ip_src_addr[4] = { 192, 168, 0, 13 };
	unsigned char ip_dst_addr[4] = { 192, 168, 0, 11 };

	eh_eth = create_eth_header(eth_mac_src_addr, eth_mac_dst_addr);
	eh_wlan = create_eth_header(wlan_mac_src_addr, wlan_mac_dst_addr);

	ih_eth = create_ip_header(0, ip_src_addr, ip_dst_addr);
	ih_wlan = create_ip_header(0, ip_src_addr, ip_dst_addr);

	puts("");
	puts("");

	printf("Checksum: %d\n", calc_ip_checksum(&ih_eth));
	printf("Checksum: %d\n", csum(&ih_eth));

	//pthread_join(h_wire, NULL);
	//pthread_join(h_wireless, NULL);

	pthread_mutex_destroy(&mutex);
	sem_destroy(&semaphore);

	free(buffer);

	return EXIT_SUCCESS;
}

void* wire(void *param) {
	pcap_t* wire_handler;
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

		exit(-1);
	}

	printf("SELECTED: %s\n\n", device->name);

	// Open the capture device
    if ((wire_handler = pcap_open_live( device->name,		// name of the device
                              65536,						// portion of the packet to capture (65536 guarantees that the whole packet will be captured on all the link layers)
                              1,							// promiscuous mode
                              500,							// read timeout
							  error_buffer					// buffer where error message is stored
							  )) == NULL)
    {
        printf("\nUnable to open the adapter. %s is not supported by libpcap/WinPcap\n", device->name);
        pcap_freealldevs(devices);

		exit(-1);
    }

	sem_post(&semaphore);
	sleep(1);
	sem_wait(&semaphore);

	pcap_freealldevs(devices);
}

void* wireless(void *param) {
	pcap_t* wireless_handler;
	pcap_if_t *device, *devices;

	unsigned char error_buffer[PCAP_ERRBUF_SIZE];


	sem_wait(&semaphore);

	if(pcap_findalldevs(&devices, error_buffer) == -1) {
		printf("Error in pcap_findalldevs: %s\n", error_buffer);

		exit(-1);
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
	if ((wireless_handler = pcap_open_live( device->name,		// name of the device
							  65536,						// portion of the packet to capture (65536 guarantees that the whole packet will be captured on all the link layers)
							  1,							// promiscuous mode
							  500,							// read timeout
							  error_buffer					// buffer where error message is stored
							  )) == NULL)
	{
		printf("\nUnable to open the adapter. %s is not supported by libpcap/WinPcap\n", device->name);
		pcap_freealldevs(devices);

		exit(-1);
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
		exit(-1);
    }

	// Pick one device from the list
    printf("Enter the interface number (1-%d):", i);
    scanf("%d", &device_num);

    if(device_num < 1 || device_num > i) {
        printf("\nInterface number out of range.\n");
    	exit(-1);
    }

     // Jump to the selected device
    for(device = devices, i = 0; i < device_num-1; device=device->next, i++);

	return device;
}
