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
static FILE *in_file;
static unsigned char *buffer;
static size_t size;

static sem_t semaphore;
static pthread_mutex_t mutex;
static pthread_t h_wire, h_wireless;

/* Protocol based global variables */
static ethernet_header eh_eth, eh_wlan;
static ip_header ih_eth, ih_wlan;
static udp_header uh_eth, uh_wlan;
static r_udp_header ruh_eth, ruh_wlan;
static packet pack_eth, pack_wlan;

static unsigned char *ppack;

//RPI
static unsigned char eth_mac_src_addr[6] = { 0xb8, 0x27, 0xeb, 0x73, 0x1e, 0xb2 };
static unsigned char wlan_mac_src_addr[6] = { 0x00, 0x0f, 0x60, 0x04, 0x5d, 0xca };
static unsigned char eth_ip_src_addr[4] = { 10, 81, 35, 53 };
static unsigned char wlan_ip_src_addr[4] = { 192, 168, 0, 11 };

//PC
static unsigned char eth_mac_dst_addr[6]  = { 0x38, 0xd5, 0x47, 0xde, 0xea, 0xa2 };
static unsigned char wlan_mac_dst_addr[6] = { 0xec, 0x08, 0x6b, 0x08, 0x52, 0x19 };
static unsigned char eth_ip_dst_addr[4] = { 10, 81, 35, 40 };
static unsigned char wlan_ip_dst_addr[4] = { 192, 168, 0, 13 };

/* Functions used */
void* wire(void *param);
void* wireless(void *param);
pcap_if_t* select_device(pcap_if_t* devices);


int main() {

	pthread_mutex_init(&mutex, NULL);
	sem_init(&semaphore, 0, 0);

	in_file = fopen("../in_file.png", "rb");

	size = load_file(in_file, &buffer);

	printf("%lf\n", (float)size/512);

	puts("");

	pthread_create(&h_wire, NULL, wire, 0);
	//pthread_create(&h_wireless, NULL, wireless, 0);

	pthread_join(h_wire, NULL);
	//pthread_join(h_wireless, NULL);

	pthread_mutex_destroy(&mutex);
	sem_destroy(&semaphore);

	fclose(in_file);

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
                              1,							// read timeout
							  error_buffer					// buffer where error message is stored
							  )) == NULL)
    {
        printf("\nUnable to open the adapter. %s is not supported by libpcap/WinPcap\n", device->name);
        pcap_freealldevs(devices);

		exit(-1);
    }

	if(pcap_datalink(wire_handler) != DLT_EN10MB)
	{
		printf("\nThis program works only on Ethernet networks.\n");

		exit(-1);
	}

	eh_eth = create_eth_header(eth_mac_src_addr, eth_mac_dst_addr);
	ih_eth = create_ip_header(MAX_PAY, eth_ip_src_addr, eth_ip_dst_addr);
	uh_eth = create_udp_header(SRC_PORT, DST_PORT, MAX_PAY);

	ruh_eth = create_r_udp_header(0, 0);

	eh_wlan = create_eth_header(wlan_mac_src_addr, wlan_mac_dst_addr);
	ih_wlan = create_ip_header(MAX_PAY, wlan_ip_src_addr, wlan_ip_dst_addr);
	uh_wlan = create_udp_header(SRC_PORT, DST_PORT, MAX_PAY);

	for(int i=0; i < 452; i++) {
		ruh_eth = create_r_udp_header(i, 0);

		pack_eth = create_packet(eh_eth, ih_eth, uh_eth, ruh_eth, buffer+i*MAX_PAY, MAX_PAY);
		ppack = (unsigned char*)&pack_eth;

		pcap_sendpacket(wire_handler, ppack, sizeof(packet) + MAX_PAY);
		printf(". ");
	}

	pcap_freealldevs(devices);
}

void* wireless(void *param) {
	pcap_t* wireless_handler;
	pcap_if_t *device, *devices;

	unsigned char error_buffer[PCAP_ERRBUF_SIZE];

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

	eh_wlan = create_eth_header(wlan_mac_src_addr, wlan_mac_dst_addr);
	ih_wlan = create_ip_header(MAX_PAY, wlan_ip_src_addr, wlan_ip_dst_addr);
	uh_wlan = create_udp_header(SRC_PORT, DST_PORT, MAX_PAY);

	for(int i=0; i < 452; i++) {
		ruh_wlan = create_r_udp_header(i, 0);

		pack_wlan = create_packet(eh_wlan, ih_wlan, uh_wlan, ruh_wlan, buffer+i*MAX_PAY, MAX_PAY);
		ppack = (unsigned char*)&pack_wlan;

		pcap_sendpacket(wireless_handler, ppack, sizeof(packet) + MAX_PAY);
		printf(". ");
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
