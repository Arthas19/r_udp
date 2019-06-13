#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pcap.h>
#include <unistd.h>
#include <pthread.h>
#include <semaphore.h>
#include <netinet/in.h>

#include "protocol_headers.h"
#include "file_io.c"


/* Global variables */
static FILE *eth_out_file, *wlan_out_file;

static sem_t semaphore;
static pthread_mutex_t mutex;
static pthread_t h_wire, h_wireless;

static unsigned char filter[] = "ip src host 10.81.31.51";


/* Functions used */
void* wire(void*);
void* wireless(void*);
pcap_if_t* select_device(pcap_if_t*);
void eth_packet_handler(unsigned char*, const struct pcap_pkthdr*, const unsigned char*);
void wlan_packet_handler(unsigned char*, const struct pcap_pkthdr*, const unsigned char*);


int main() {
	pthread_mutex_init(&mutex, NULL);
	sem_init(&semaphore, 0, 0);

	eth_out_file = fopen("../out_file.png", "a+");
	wlan_out_file = fopen("../out_file.png", "a+");

	pthread_create(&h_wire, NULL, wire, 0);
	//pthread_create(&h_wireless, NULL, wireless, 0);

	pthread_join(h_wire, NULL);
	//pthread_join(h_wireless, NULL);

	pthread_mutex_destroy(&mutex);
	sem_destroy(&semaphore);

	fclose(eth_out_file);
	fclose(wlan_out_file);

	return EXIT_SUCCESS;
}

void* wire(void *param) {
	pcap_t *wire_handler;
	pcap_if_t *device, *devices;
	unsigned char error_buffer[PCAP_ERRBUF_SIZE];
	unsigned int netmask;
	struct bpf_program fcode;
	struct pcap_pkthdr *packet_header;
	const unsigned char *packet_data;

	if(pcap_findalldevs(&devices, error_buffer) == -1)
	{
		printf("Error in pcap_findalldevs: %s\n", error_buffer);

		exit(-1);
	}

	printf("WIRE:\n");

	device = select_device(devices);

	if (device == NULL) {
		pcap_freealldevs(devices);
		sem_post(&semaphore);

		exit(-1);
	}

	printf("\nSELECTED: %s\n\n", device->name);

	// Open the capture device
	if ((wire_handler = pcap_open_live( device->name,		// name of the device
							  			65536,				// portion of the packet to capture (65536 guarantees that the whole packet will be captured on all the link layers)
							  			1,					// promiscuous mode
							  			1,					// read timeout
							  			error_buffer		// buffer where error message is stored
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

	printf("\nListening on %s...\n", device->name);

	pcap_freealldevs(devices);

	//                   226 ~ 225
	pcap_loop(wire_handler, 452, eth_packet_handler, NULL);
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

	printf("WIRELESS:\n");

	device = select_device(devices);

	if (device == NULL) {
		pcap_freealldevs(devices);

		exit(-1);
	}

	printf("\nSELECTED: %s\n\n", device->name);

	// Open the capture device
	if ((wireless_handler = pcap_open_live( device->name,	// name of the device
							  				65536,			// portion of the packet to capture (65536 guarantees that the whole packet will be captured on all the link layers)
							  				1,				// promiscuous mode
							  				500,			// read timeout
							  				error_buffer	// buffer where error message is stored
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

	pcap_freealldevs(devices);

	pcap_loop(wireless_handler, 226, wlan_packet_handler, NULL);
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

void eth_packet_handler(unsigned char* param,
						const struct pcap_pkthdr* packet_header,
						const unsigned char* packet_data) {

	size_t size, offset;

	udp_header *uh = (udp_header*)(packet_data + sizeof(ethernet_header) + 20);
	r_udp_header *ruh = (r_udp_header*)(packet_data + sizeof(ethernet_header) + 20 + sizeof(udp_header));
	unsigned char *data;

	size = ntohs(uh->datagram_length) - sizeof(udp_header) - sizeof(r_udp_header);
	offset = ntohs(ruh->seq_num);

	data = (unsigned char*)(packet_data + sizeof(ethernet_header) + 20 + sizeof(udp_header) + sizeof(r_udp_header));
	write_to_file(eth_out_file, data, size, offset);

	printf("%ld\n", size);
	printf("%ld\n", offset);
}

void wlan_packet_handler(unsigned char* param,
						 const struct pcap_pkthdr* packet_header,
						 const unsigned char* packet_data) {

	size_t size, offset;

	udp_header *uh = (udp_header*)(packet_data + sizeof(ethernet_header) + 20);
	r_udp_header *ruh = (r_udp_header*)(packet_data + sizeof(ethernet_header) + 20 + sizeof(udp_header));
	unsigned char *data;

	size = ntohs(uh->datagram_length) - sizeof(udp_header) - sizeof(r_udp_header);
	offset = ntohs(ruh->seq_num);

	data = (unsigned char*)(packet_data + sizeof(ethernet_header) + 20 + sizeof(udp_header) + sizeof(r_udp_header));
	write_to_file(wlan_out_file, data, size, offset);

	printf("%ld\n", size);
	printf("%ld\n", offset);
}
