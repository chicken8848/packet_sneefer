#ifndef HACKING_NETWORK_H_
#define HACKING_NETWORK_H_
#include <stdio.h>

#define ETHER_ADDR_LEN 6
#define ETHER_HDR_LEN 14

void dump(const unsigned char *data_buffer, const unsigned int length) {
  unsigned char byte;
  unsigned int i, j;
  for (i = 0; i < length; i++) {
    byte = data_buffer[i];
    printf("%02x ", data_buffer[i]); // display hex
    if (((i%16) == 15) || (i==length-1)) {
      for (j=0; j < 15 - (i%16); j++) printf("    ");
      printf("| ");
      for (j=(i-(i%16)); j <= i; j++) {
        byte = data_buffer[i];
        if ((byte > 31) && (byte < 127))
          printf("%c", byte);
        else
          printf(".");
      }
      printf("\n"); // end of the dump line each line would be 16 bytes
    }
  }
}

struct ether_hdr {
  unsigned char ether_dest_addr[ETHER_ADDR_LEN]; // Destination MAC address
  unsigned char ether_src_addr[ETHER_ADDR_LEN]; // Source MAC address
  unsigned short ether_type; // Type of Ethernet packet
};

// Reference: https://www.rfc-editor.org/rfc/rfc791.html
// Reference: /usr/include/netinet/ip.h
// TODO: Version and Header length host -> network byte order
struct ip_hdr {
  unsigned char ip_version_and_header_length; // Version and header length, 1 byte
  unsigned char ip_tos; // Type of service, 1 byte
  unsigned short ip_len; // total len, 2 bytes
  unsigned short ip_id; // identification number, 2 bytes
  unsigned short ip_frag_offset; // Flags + fragment offset, 2 bytes
  unsigned char ip_ttl; // Time to live, 1 byte
  unsigned char ip_type; // Protocol type
  unsigned short ip_checksum; // Header checksum
  unsigned int ip_src_addr; // Source IP address
  unsigned int ip_dest_addr; // destination ip address
};

// Reference: https://www.rfc-editor.org/rfc/rfc793.html
// Reference: /usr/include/netinet/tcp.h
// TODO: offset and reserved host -> network byte order
struct tcp_hdr {
  unsigned short tcp_src_port;
  unsigned short tcp_dest_port;
  unsigned int tcp_seq;
  unsigned int tcp_ack;
  unsigned char reserved:4; // 4 bits from the 6 bits of reserved space
  unsigned char tcp_offset:4; // TCP data offset for little-endian host
  unsigned char tcp_flags; // TCP flags (and 2 bits from reserved space)
#define TCP_FIN  0x01
#define TCP_SYN  0x02
#define TCP_RST  0x04
#define TCP_PUSH 0x08
#define TCP_ACK  0x10
#define TCP_URG  0x20
  unsigned short tcp_window; // TCP window size
  unsigned short tcp_checksum; // TCP checksum
  unsigned short tcp_urgent; // TCP Urgent Pointer
};


#endif // HACKING_NETWORK_H_
