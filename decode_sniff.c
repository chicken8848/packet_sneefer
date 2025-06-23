/**********************************************************************************/
/* The MIT License (MIT)                                                          */
/*                                                                                */
/* Copyright (c) 2015 Maxim Baz                                                   */
/*                                                                                */
/* Permission is hereby granted, free of charge, to any person obtaining a copy   */
/* of this software and associated documentation files (the "Software"), to deal  */
/* in the Software without restriction, including without limitation the rights   */
/* to use, copy, modify, merge, publish, distribute, sublicense, and/or sell      */
/* copies of the Software, and to permit persons to whom the Software is          */
/* furnished to do so, subject to the following conditions:                       */
/*                                                                                */
/* The above copyright notice and this permission notice shall be included in all */
/* copies or substantial portions of the Software.                                */
/*                                                                                */
/* THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR     */
/* IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,       */
/* FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE    */
/* AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER         */
/* LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,  */
/* OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE  */
/* SOFTWARE.                                                                      */
/**********************************************************************************/
#include <pcap.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include "hacking-network.h"

// If using wifi, wlan needs to be put into monitor mode
// Easiest way: https://www.aircrack-ng.org/doku.php?id=airmon-ng

void pcap_fatal(const char *, const char *);
void decode_ethernet(const u_char *);
void decode_ip(const u_char *);
u_int decode_tcp(const u_char *);

void caught_packet(u_char *, const struct pcap_pkthdr *, const u_char *);

int main() {
  struct pcap_pkthdr cap_header;
  const u_char *packet, *pkt_data;
  char errbuf[PCAP_ERRBUF_SIZE];
  char *device;
  pcap_t *pcap_handle;

  device = pcap_lookupdev(errbuf);
  if (device == NULL)
    pcap_fatal("pcap_lookupdev", errbuf);

  printf("Sniffing on device %s\n", device);

  pcap_handle = pcap_open_live(device, 4096, 1, 0, errbuf);
  if (pcap_handle == NULL)
    pcap_fatal("pcap_open_live", errbuf);

  pcap_loop(pcap_handle, 3, caught_packet, NULL);

  pcap_close(pcap_handle);
}

void caught_packet(u_char *user_args, const struct pcap_pkthdr *cap_header, const u_char *packet) {
  int tcp_header_length, total_header_size, pkt_data_len;
  u_char *pkt_data;

  printf("=== Got a %d byte packet ===\n", cap_header->len);

  // we are adding to the pointer in the packet, so we can get to different headers
  decode_ethernet(packet);
  decode_ip(packet+ETHER_HDR_LEN);
  tcp_header_length = decode_tcp(packet+ETHER_HDR_LEN+sizeof(struct ip_hdr)); // returns u_int since tcp header length is variable

  total_header_size = ETHER_HDR_LEN+sizeof(struct ip_hdr)+tcp_header_length;
  pkt_data = (u_char *)packet + total_header_size; // pkt_data points to the data portion
  if (pkt_data_len > 0) {
    printf("\t\t\t%u bytes of packet data\n", pkt_data_len);
    dump(pkt_data, pkt_data_len);
  } else
    printf("\t\t\tNo Packet Data\n");
}

void pcap_fatal(const char *failed_in, const char *errbuf) {
  printf("Fatal Error in %s: %s\n", failed_in, errbuf);
  exit(1);
}

void decode_ethernet(const u_char *header_start) {
  int i;
  const struct ether_hdr *ethernet_header;

  // we can do this because of the way we defined our struct
  // structs are defined as contiguous memory, and that's what the packet is
  ethernet_header = (const struct ether_hdr *) header_start;

  printf("[[ Layer 2 :: Ethernet Header ]]\n");
  printf("[ Source: %02x ", ethernet_header->ether_src_addr[0]);
  for(i=1; i < ETHER_ADDR_LEN; i++)
    printf(":%02x", ethernet_header->ether_src_addr[i]);
  printf("\tType: %hu ]\n", ethernet_header->ether_type);
}

void decode_ip(const u_char *header_start) {
  const struct ip_hdr *ip_header;
  struct in_addr *ip_src_addr = malloc(sizeof(struct in_addr));
  struct in_addr *ip_dst_addr = malloc(sizeof(struct in_addr));

  ip_header = (const struct ip_hdr *) header_start;
  ip_src_addr->s_addr = ip_header->ip_src_addr;
  ip_dst_addr->s_addr = ip_header->ip_dest_addr;

  printf("\t(( Layer 3 ::: IP Header ))\n");
  printf("\t( Source: %s\t", inet_ntoa(*ip_src_addr));
  printf("Dest: %s )\n", inet_ntoa(*ip_dst_addr));
  printf("\t( Type: %u\t", (u_int) ip_header->ip_type);
  printf("ID: %hu\tLength: %hu )\n", ntohs(ip_header->ip_id), ntohs(ip_header->ip_len));

  free(ip_src_addr);
  free(ip_dst_addr);
}

u_int decode_tcp(const u_char *header_start) {
  u_int header_size;
  const struct tcp_hdr *tcp_header;

  tcp_header = (const struct tcp_hdr *)header_start;
  header_size = 4 * tcp_header->tcp_offset;

  printf("\t\t{{ Layer 4 :::: TCP Header }}\n");
  printf("\t\t{ Src Port: %hu\t", ntohs(tcp_header->tcp_src_port));
  printf("Dest Port: %hu }\n", ntohs(tcp_header->tcp_dest_port));
  printf("\t\t{ Seq #: %u\t", ntohl(tcp_header->tcp_seq));
  printf("Ack #: %u }\n", ntohl(tcp_header->tcp_ack));
  printf("\t\t{ Header Size: %u\tFlags: ", header_size);
  // the right way to check for flags
  if(tcp_header->tcp_flags & TCP_FIN) printf("FIN ");
  if(tcp_header->tcp_flags & TCP_SYN) printf("SYN ");
  if(tcp_header->tcp_flags & TCP_RST) printf("RST ");
  if(tcp_header->tcp_flags & TCP_PUSH) printf("PUSH ");
  if(tcp_header->tcp_flags & TCP_ACK) printf("ACK ");
  if(tcp_header->tcp_flags & TCP_URG) printf("URG ");
  printf(" }\n");

  return header_size;
}
