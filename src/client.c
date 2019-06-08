#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <semaphore.h>

#include <unistd.h>
#include <netinet/in.h>

#include "protocol_headers.h"

#define BUF 512


/* Global variables */
static FILE *out_file;

static sem_t semaphore;
static pthread_mutex_t mutex;
static pthread_t h_wire, h_wireless;

static int i_packet = 0;

//rpi
//eth0  11
//wlan0 10

//pc
//eth0  14
//wlan0 12

static unsigned char filter[] = "ip src host 192.168.0.10";


/* Functions used */
void* wire(void *param);
void* wireless(void *param);
pcap_if_t* select_device(pcap_if_t* devices);


int main() {

	unsigned char buffer[BUF];

	pthread_mutex_init(&mutex, NULL);
	sem_init(&semaphore, 0, 0);

	//pthread_create(&h_wire, NULL, wire, 0);
	pthread_create(&h_wireless, NULL, wireless, 0);

	//pthread_join(h_wire, NULL);
	pthread_join(h_wireless, NULL);

	pthread_mutex_destroy(&mutex);
	sem_destroy(&semaphore);

	return EXIT_SUCCESS;
}

void* wire(void *param) {
	pcap_t *wire_handler;
	pcap_if_t *device, *devices;

	unsigned char error_buffer[PCAP_ERRBUF_SIZE];
	unsigned int netmask;
	struct bpf_program fcode;

	if(pcap_findalldevs(&devices, error_buffer) == -1)
	{
		printf("Error in pcap_findalldevs: %s\n", error_buffer);

		exit(-1);
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

	// setting the filter
	if (!device->addresses->netmask)
		netmask = 0;
	else
		netmask = ((struct sockaddr_in *)(device->addresses->netmask))->sin_addr.s_addr;

	if (pcap_compile(wire_handler, &fcode, filter, 1, netmask) < 0) {
		printf("\nInvalid filter!\n");
		exit(-1);
	}

	if (pcap_setfilter(wire_handler, &fcode) < 0) {
		printf("\nUnable to set the filter!\n");
		exit(-1);
	}

	pcap_freealldevs(devices);
}

void* wireless(void *param) {
	pcap_t *wireless_handler;
	pcap_if_t *device, *devices;

	unsigned char error_buffer[PCAP_ERRBUF_SIZE];
	unsigned int netmask;
	struct bpf_program fcode;
	struct pcap_pkthdr *packet_header;
	const unsigned char *packet_data;

	if(pcap_findalldevs(&devices, error_buffer) == -1) {
		printf("Error in pcap_findalldevs: %s\n", error_buffer);

		exit(-1);
	}

	printf("%s\n", "WIRELESS:");

	device = select_device(devices);

	if (device == NULL) {
		pcap_freealldevs(devices);

		exit(-1);
	}

	printf("SELECTED: %s\n\n", device->name);

	// Open the capture device
	if ((wireless_handler = pcap_open_live( device->name,	// name of the device
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

	// Check the link layer. We support only Ethernet for simplicity.
	if(pcap_datalink(wireless_handler) != DLT_EN10MB) {
		printf("\nThis program works only on Ethernet networks.\n");

		exit(-1);
	}

	// setting the filter
	if (!device->addresses->netmask)
		netmask = 0;
	else
		netmask = ((struct sockaddr_in *)(device->addresses->netmask))->sin_addr.s_addr;

	if (pcap_compile(wireless_handler, &fcode, filter, 1, netmask) < 0) {
		printf("\nInvalid filter!\n");

	 	exit(-1);
	}

	if (pcap_setfilter(wireless_handler, &fcode) < 0) {
		printf("\nUnable to set the filter!\n");

		exit(-1);
	}

    printf("\nListening on %s...\n", device->name);

	while((pcap_next_ex(wireless_handler, &packet_header, &packet_data)) >= 0) {
		ethernet_header *eh;
		ip_header *ih;
		udp_header *uh;
		r_udp_header *ruh;
		unsigned char *data;

		int ip_len;
		int len;

		eh = (ethernet_header*)packet_data;
		ih = (ip_header*)(packet_data + sizeof(ethernet_header));
		ip_len = ih->header_length*4;
		uh = (udp_header*)(ih + ip_len);
		data = (unsigned char*)(uh + sizeof(udp_header) + sizeof(r_udp_header));

		printf("%c ", *data);
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
