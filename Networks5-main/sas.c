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

/*
* Spoofer.c
*
written by Maya Rom & Yogev Ofir
id's: 207485251 & 322719881
date: 01/2023
*/

// library
// library
#include "libsniffspoof.h"

int main()
{
    pcap_t *handle;                                               // Session handle
    char ebuffer[PCAP_ERRBUF_SIZE];                                // Error string
    struct bpf_program fp;                                        // The compiled filter expression
    char *devName = netInterfaceSelect_spoofer(ebuffer, handle); // Select the network interface to sniff on

    // Open the device for sniffing
    int result = open_sniffing_device(devName, ebuffer, &handle);
    if (result != 0)
    {
        printf("Error: %s\n", ebuffer);
        return -1;
    }

    // Specify a filter - in this assigment , we request to catch only capture ICMP packets
    char *filter_exp = "icmp"; // filter expression
    printf(" The filter is: %s\n", filter_exp);

    bpf_u_int32 net; // The IP of our sniffing device

    // compile the filter expression

    // catch errors
    int result2 = set_filter(handle, filter_exp);
    if (result2 == 0) {
    // filter set successfully
    //*** Capture packets - the callback function is takeAPacket() ***
    pcap_loop(handle, -1, takeAPacket, NULL); // capture packets
    pcap_close(handle);
    } else {
    // filter couldn't be set, check the error message
    printf("Error: %s\n", pcap_geterr(handle));
    }
    return 0;
}

/**
 * this function is called every time a packet is captured by the sniffer
 * @param args - arguments passed to the callback function
 * @param header - contains information about the packet
 * @param packet - the packet itself
 */

void takeAPacket(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
    int packet_len = header->len;
    if (packet_len >= sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct icmphdr)) {
        int ethernet_header_len = sizeof(struct ethhdr) + 2;
        struct iphdr *ip_header = (struct iphdr *)(packet + ethernet_header_len);
        struct icmphdr *icmp_header = (struct icmphdr *)(packet + ethernet_header_len + sizeof(struct iphdr));
        if (icmp_header->type == ICMP_ECHO) {
            struct sockaddr_in dest;
            dest.sin_addr.s_addr = ip_header->daddr;
            catchNReplay(dest, packet, ethernet_header_len, packet_len, icmp_header);
        }
        if (ip_header-> protocol == 1)

        {
            printf("-----------------ICMP-----------------\n\n");
            struct icmphdr *icmp = (struct icmphdr *)(packet + ethernet_header_len + sizeof(struct iphdr));
            printf("     |icmp type: %d\n", icmp->type);
            struct tcphdr *tcph = (struct tcphdr *)(packet + sizeof(struct iphdr) + ethernet_header_len);
            printf("     |icmp code: %d\n", icmp->code);
            printf("     |icmp checksum: %d\n", icmp->checksum);
            printf("     |icmp id: %d\n", icmp->un.echo.id);
            printf("     |icmp sequence: %d\n", icmp->un.echo.sequence);
            printf("     |size of icmp: %ld\n", sizeof(struct icmphdr));
            int dataLen = packet_len - (ethernet_header_len + sizeof(struct iphdr) + sizeof(struct icmphdr));
            printf("     |data length: %d\n", dataLen);
            if (dataLen > 0)
            {
                printf("     |data: ");
                for (int i = 0; i < dataLen; i++)
                {
                    printf("%c", packet[ethernet_header_len + sizeof(struct iphdr) + sizeof(struct icmphdr) + i]);
                }
                printf("\n");
            }
        }
    }
}

int send_reply(char *reply, int length, struct sockaddr_in dest)
{

    int sock = socket(AF_INET, SOCK_RAW, IPPROTO_RAW); // create a raw socket

    if (sock < 0) // catch error creating the socket
    {
        perror("Sorry, the is a problem creating the socket ...");
        return -1;
    }
    int enable = 1; // enable IP_HDRINCL - we want to include the IP header in the packet

    setsockopt(sock, IPPROTO_IP, IP_HDRINCL, &enable, sizeof(enable)); // set the socket options

    // send the reply
    int i = sendto(sock, reply, length, 0, (struct sockaddr *)&dest, sizeof(dest));

    // catch errors sending the reply
    if (i < 0)
    {
        perror("Sorry, there is a problem sending the reply ...");
        return -1;
    }
    // print success message
    printf("Yes! reply sent successfully\n");

    // close the socket when we don't need it anymore - we already sent the reply
    close(sock);
    return i; // return the number of bytes sent
}


char *netInterfaceSelect_spoofer(char *ebuffer, pcap_t *handle) {
    int packets_number = 1, n;
    pcap_if_t *alldevsp, *device;
    char *devs[100][100];

    printf("Finding available devices ... ");
    int result = pcap_findalldevs(&alldevsp, ebuffer);
    switch (result) {
        case 0:
            printf("Done\n");
            break;
        default:
            printf("Error finding devices : %s", ebuffer);
            return 1;
    }

    // Print the available devices
    printf("Available Devices are :\n");
    device = alldevsp;
    while (device != NULL) {
        printf("%d. %s - %s\n", packets_number, device->name, device->description);
        if (device->name != NULL) {
            strcpy(devs[packets_number], device->name);
        }
        packets_number++;
        device = device->next;
    }

    // Ask user which device to sniff
    printf("Enter the number of the device you want to sniff : ");
    scanf("%d", &n);
    if (handle == NULL) {
        fprintf(stderr, "Couldn't open device %s : %s\n", devs[n], ebuffer);
        return 1;
    }
    printf("Done\n");
    char *devName = devs[n];
    return devName;
}

// Compute checksum (RFC 1071).
unsigned short calculate_checksum(unsigned short *paddress, int len) {
    unsigned int sum = 0;
    int i;

    for (i = 0; i < len; i++) {
        sum += paddress[i];
    }

    while (sum >> 16) {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    return (unsigned short) ~sum;
}


char *allocate_reply_packet(const u_char *packet, int etherHeader, int length) {
    // allocate memory for the reply packet
    char *reply = (char *) malloc(length - etherHeader);
    return reply;
}

void copy_headers(const u_char *packet, int ether_header_len, char *reply) {
    struct iphdr *original_ip_header = (struct iphdr *)(packet + ether_header_len);
    struct icmphdr *original_icmp_header = (struct icmphdr *)(packet + ether_header_len + sizeof(struct iphdr));

    struct iphdr *reply_ip_header = (struct iphdr *) reply;
    struct icmphdr *reply_icmp_header = (struct icmphdr *)(reply + sizeof(struct iphdr));

    // copy the ip header from the packet we want to reply to
    memcpy(reply_ip_header, original_ip_header, sizeof(struct iphdr));
    reply_ip_header->saddr = inet_addr("1.2.3.4"); // change source address
    reply_ip_header->daddr = inet_addr("10.9.0.6"); // change destination address

    // copy the icmp header from the packet we want to reply to
    memcpy(reply_icmp_header, original_icmp_header, sizeof(struct icmphdr));
    reply_icmp_header->type = ICMP_ECHOREPLY;  // change type to ICMP_ECHOREPLY for echo reply
    reply_icmp_header->code = 0;  // change code to 0 for echo reply
    reply_icmp_header->checksum = 0; // reset the checksum
}

void copy_data(const u_char *packet, int ether_header_len, int packet_len, char *reply) {
    copy_headers(packet, ether_header_len, reply);
    char *original_data = (char *)(packet + ether_header_len + sizeof(struct iphdr) + sizeof(struct icmphdr));
    int data_len = packet_len - ether_header_len - sizeof(struct iphdr) - sizeof(struct icmphdr);
    char *reply_data = (char *)(reply + sizeof(struct iphdr) + sizeof(struct icmphdr));

    if (data_len > 0) {
        // copy the data from the packet we want to reply to
        memcpy(reply_data, original_data, data_len);
    }
}

void create_reply_packet(const u_char *packet, int etherHeader, int length, char *reply) {
    copy_data(packet, etherHeader, length, reply);
    struct icmphdr *ICMPHeader_reply = (struct icmphdr *)(reply + sizeof(struct iphdr));
    int dataLen = length - etherHeader - sizeof(struct iphdr) - sizeof(struct icmphdr);
    ICMPHeader_reply->checksum = calculate_checksum((unsigned short *)ICMPHeader_reply, sizeof(struct icmphdr) + dataLen);
}

int open_sniffing_device(char *device_name, char *error_buffer, pcap_t **handle) {
    printf("Opening device %s for sniffing...\n", device_name);
    *handle = pcap_open_live(device_name, 65536, 1, 1, error_buffer);
    if (*handle == NULL) {
        fprintf(stderr, "Error opening device %s: %s\n", device_name, error_buffer);
        return 2;
    }
    printf("Device %s opened successfully\n", device_name);
    return 0;
}

int set_filter(pcap_t *handle, char *filter_exp, bpf_u_int32 net, struct bpf_program fp) {
    int err = pcap_compile(handle, &fp, filter_exp, 0, net);
    if (err != 0) {
        fprintf(stderr, "Error compiling filter: %s\n", pcap_geterr(handle));
        return 1;
    }
    err = pcap_setfilter(handle, &fp);
    if (err != 0) {
        fprintf(stderr, "Error setting filter: %s\n", pcap_geterr(handle));
        return 2;
    }
    printf("Filter successfully set, starting sniffing...\n");
    return 0;
}

void catchNReplay(struct sockaddr_in dest, const char* packet, int ether_header_len, int packet_len, struct iphdr* IPHeader) {
    printf("Caught ICMP echo request to %s\n", inet_ntoa(dest.sin_addr));
    char *reply = allocate_reply_packet(packet, ether_header_len, packet_len);
    create_reply_packet(packet, ether_header_len, packet_len, reply);
    dest.sin_family = AF_INET;
    int bytes_sent = send_reply(reply, packet_len - ether_header_len, dest);
    if (bytes_sent == -1) {
        printf("Error sending reply\n");
    } else {
        printf("Sent reply: %d bytes\n", bytes_sent);
    }
}