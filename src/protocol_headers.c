#include "protocol_headers.h"

ethernet_header create_eth_header(unsigned char *src, unsigned char *dest) {
    ethernet_header eh;

    memcpy(eh.src_address, src, 6);
    memcpy(eh.dest_address, dest, 6);
    eh.type = htons(TYPE);

    return eh;
}
