/* PROTOCOL HEADERS */
#ifndef PROTOCOL_HEADERS_H
#define PROTOCOL_HEADERS_H

#include <string.h>
#include <arpa/inet.h>

// -----------------------------------------------------------------------------
// Ethernet header, all constants and functions

#define TYPE 0x0800

typedef struct ethernet_header {
	unsigned char dest_address[6];		// Destination address
	unsigned char src_address[6];		// Source address
	unsigned short type;				// Type of the next layer
} ethernet_header;

ethernet_header create_eth_header(unsigned char *src_addr, unsigned char *dst_addr);

// -----------------------------------------------------------------------------

// IPv4 header

#define FRAGMLESS 0x4000
#define UDP       0x11
#define TTL       0x11
#define ID        0x13

typedef struct ip_header {
	unsigned char header_length :4;	// Internet header length (4 bits)
	unsigned char version :4;		// Version (4 bits)
	unsigned char tos;				// Type of service
	unsigned short length;			// Total length
	unsigned short identification;	// Identification
	unsigned short fragm;  			// Flags (3 bits) & Fragment offset (13 bits)
	unsigned char ttl;				// Time to live
	unsigned char next_protocol;	// Protocol of the next layer
	unsigned short checksum;		// Header checksum
	unsigned char src_addr[4];		// Source address
	unsigned char dst_addr[4];		// Destination address
} ip_header;

ip_header create_ip_header(size_t, unsigned char*, unsigned char*);
unsigned short calc_ip_checksum(ip_header*);

// -----------------------------------------------------------------------------

// UDP header

#define SRC_PORT 2919
#define DST_PORT 2919

typedef struct udp_header {
	unsigned short src_port;		// Source port
	unsigned short dest_port;		// Destination port
	unsigned short datagram_length;	// Length of datagram including UDP header and data
	unsigned short checksum;		// Header checksum ???
} udp_header;

udp_header create_udp_header(unsigned short, unsigned short, unsigned short);

// -----------------------------------------------------------------------------

// R_UDP

typedef struct r_udp_header {
	unsigned short seq_num;
	unsigned short ack_num;
	//unsigned short flags;     // ???
	//unsigned short win_size;  // ???
	// + 4 * 4 Byte-a -> 16 Byte-a EXTRA na UDP
} r_udp_header;

r_udp_header create_r_udp_header(unsigned short, unsigned short);

// -----------------------------------------------------------------------------

// FULL

#define MAX_PAY 512

typedef struct packet_st {
	ethernet_header eh;
	ip_header ih;
	udp_header uh;
	r_udp_header ruh;
	unsigned char payload[MAX_PAY];
} packet;

packet create_packet(ethernet_header, ip_header, udp_header, r_udp_header, unsigned char*, size_t);

#endif
