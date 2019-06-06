#include "protocol_headers.h"

ethernet_header create_eth_header(unsigned char *src_addr,
                                  unsigned char *dst_addr) {
    ethernet_header eh;

    memcpy(eh.src_address, src_addr, 6);
    memcpy(eh.dest_address, dst_addr, 6);
    eh.type = htons(TYPE);

    return eh;
}

ip_header create_ip_header(size_t data_size,
                           unsigned char *src_addr,
                           unsigned char *dst_addr) {
    ip_header ih;

    ih.header_length = 5;   // optional part is removed
    ih.version = 4;         // IPv4
    ih.tos = 0;             // all set to default
    ih.identification = 19; // not really necessary
    ih.length = htons(sizeof(ip_header) +
                      sizeof(udp_header) +
                      sizeof(r_udp_header) +
                      data_size);
    ih.fragm = htons(FRAGMLESS);   // fragmentation is forbidden
    ih.ttl = TTL;
    ih.next_protocol = UDP;
    ih.checksum = 0;
    memcpy(ih.src_addr, src_addr, 4);
    memcpy(ih.dst_addr, dst_addr, 4);

    //ih.checksum = calc_ip_checksum(&ih);
    ih.checksum = htons(calc_ip_checksum(&ih));

    return ih;
}

udp_header create_udp_header(unsigned short src_port,
                             unsigned short dst_port,
                             unsigned short data_size) {
    udp_header uh;

    uh.src_port = htons(src_port);
    uh.dest_port = htons(dst_port);
    uh.datagram_length = htons(sizeof(udp_header) +
                               sizeof(r_udp_header) +
                               data_size);

    return uh;
}

r_udp_header create_r_udp_header(unsigned short seq,
                                 unsigned short ack) {
    r_udp_header ruh;

    ruh.seq_num = seq;
    ruh.ack_num = ack;

    return ruh;
}

packet create_packet(ethernet_header eh,
                     ip_header ih,
                     udp_header uh,
                     r_udp_header ruh
                     unsigned char *data,
                     size_t data_size) {
    packet packet;

    packet.eh = eh;
    packet.ih = ih;
    packet.uh = uh;
    packet.ruh = ruh;

    memcpy(packet.payload, data, data_size);

    return packet;
}

unsigned short calc_ip_checksum(ip_header *ih) {
    int i;
    unsigned int sum = 0;
    unsigned short *buff = (unsigned short*)ih;

    for (i = 0; i < 10; i++)
        sum += buff[i];

    while (sum >> 16)
        sum = (sum & 0xffff) + (sum >> 16);

    return (unsigned short)(~sum);
}
