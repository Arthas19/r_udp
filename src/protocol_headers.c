#include "protocol_headers.h"

ethernet_header create_eth_header(unsigned char *src_addr, unsigned char *dst_addr) {
    ethernet_header eh;

    memcpy(eh.src_address, src_addr, 6);
    memcpy(eh.dest_address, dst_addr, 6);
    eh.type = htons(TYPE);

    return eh;
}

ip_header create_ip_header(size_t data_size, unsigned char *src_addr, unsigned char *dst_addr) {
    ip_header ih;

    ih.header_length = 5;   // optional part is removed
    ih.version = 4;         // IPv4
    ih.tos = 0;             // all set to default
    ih.identification = 19; // not really necessary
    ih.length = htons(sizeof(ip_header) + sizeof(r_udp_header) + data_size);
    ih.fragm = FRAGMLESS;   // fragmentation is forbidden
    ih.ttl = TTL;
    ih.next_protocol = UDP;
    ih.checksum = 0;
    memcpy(ih.src_addr, src_addr, 4);
    memcpy(ih.dst_addr, dst_addr, 4);

    ih.checksum = calc_ip_checksum(&ih);

    return ih;
}

unsigned short calc_ip_checksum(ip_header *ih) {
    uint8_t i;
    uint32_t sum = 0;
    uint16_t *buff = (unsigned short*)ih;

    for (i = 0; i < 10; i++)
        sum += buff[i];


    while (sum >> 16)
        sum = (sum & 0xffff) + (sum >> 16);

    return (unsigned short)(~sum);
}

unsigned short csum(ip_header *ih)
{
    uint8_t i;
    unsigned int sum = 0;
    unsigned short *buf = (unsigned short*)ih;

    for(i = 0; i < 10; i++)
        sum += *buf++;

        sum = (sum >> 16) + (sum & 0xffff);
        //sum += (sum >> 16);

    return (unsigned short)(~sum);
}
