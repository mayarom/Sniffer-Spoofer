/* library for sniffer&spoofer
written by Yogev Ofir & Maya Rom
id's: 322719881 & 207485251
date: 01/2023
*/

#ifndef LIBSNIFFSPOOF_H
#define LIBSNIFFSPOOF_H

#include <pcap.h>
#include <stdio.h>
#include <string.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <netinet/ip_icmp.h>
#include <stdlib.h>
#include <time.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include <netinet/udp.h>
#include <pcap.h>
#include <stdio.h>
#include <string.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <netinet/ip_icmp.h>
#include <stdlib.h>
#include <time.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include <netinet/udp.h>

// myHeader is the name of the struct- this struct is used to send the request to the server
// we wrote this struct here and not in sniffer.c because we need to use it in the sniffer.c and in the spoofer.c
struct myHeader
{
    // 4 bytes (32 bit)
    u_int32_t timestamp;

    // 2 bytes (16 bit)
    u_int16_t total_lenght;

    // 3 bits
    u_char saved : 3;

    // 1 byte (8 bit):
    u_char cache_flag : 1;
    u_char steps_flag : 1;
    u_char type_flag : 1;

    // 10 bits
    u_int16_t status_code : 10;

    // 2 bytes (16 bit):
    u_int16_t cache_control;
    u_int16_t padding;
};

/*
list of functions that we use in the sniffer.c and in the spoofer.c
this functions are defined in the sniffer.c and in the spoofer.c
the target of this functions is to make the code more readable and organized
*/

// functions that we use in the sniffer.c
void find_devices(pcap_if_t *alldevsp, char *ebuffer);
void select_device(int packets_number, int *n);
pcap_t *open_selected_device(char *devs[], int n, char *ebuffer);
char *select_network_interface(char *ebuffer, pcap_t *handle);
void cast_to_hex(FILE *fp, char *data, int size);
void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet);
void TCP_pack(const u_char *packet, int ethernet_header, int length);
void ICMP_pack(const u_char *packet, int ethernet_header, int length);
char *getFilter();
void print_error(int error);
int exit_program();
void print_time();
void print_choice(int choice);

// functions that we use in the spoofer.c
int send_reply(char *reply, int length, struct sockaddr_in dest);
unsigned short calculate_checksum(unsigned short *paddress, int len);
char *netInterfaceSelect_spoofer(char *ebuffer, pcap_t *handle);
int open_sniffing_device(char *devName, char *ebuffer, pcap_t **handle);
char *allocate_reply_packet(const u_char *packet, int etherHeader, int length);
void create_reply_packet(const u_char *packet, int etherHeader, int length, char *reply);
void copy_headers(const u_char *packet, int ether_header_len, char *reply);
void copy_data(const u_char *packet, int ether_header_len, int packet_len, char *reply);

#endif
