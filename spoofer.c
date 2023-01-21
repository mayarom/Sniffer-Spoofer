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
    pcap_t *handle;                                              // Session handle
    char ebuffer[PCAP_ERRBUF_SIZE];                              // Error string
    struct bpf_program fp;                                       // The compiled filter expression
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
    if (result2 == 0)
    {
        // filter set successfully
        //*** Capture packets - the callback function is got_packet() ***
        pcap_loop(handle, -1, got_packet, NULL); // capture packets
        pcap_close(handle);
    }
    else
    {
        // filter couldn't be set, check the error message
        printf("Error: %s\n", pcap_geterr(handle));
    }
    return 0;
}

// this function is called each time a packet is captured

void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{
    int packet_len = header->len;
    if (packet_len >= sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct icmphdr))
    {
        int ethernet_header_len = sizeof(struct ethhdr) + 2;
        struct iphdr *ip_header = (struct iphdr *)(packet + ethernet_header_len);
        struct icmphdr *icmp_header = (struct icmphdr *)(packet + ethernet_header_len + sizeof(struct iphdr));
        if (icmp_header->type == ICMP_ECHO)
        {
            struct sockaddr_in dest;
            dest.sin_addr.s_addr = ip_header->daddr;
            catchNReplay(dest, packet, ethernet_header_len, packet_len, icmp_header);
        }
    }
}

// this function catches the packet and sends a reply

int send_reply(char *reply, int length, struct sockaddr_in dest)
{
    int sock = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    switch (sock)
    {
    case -1:
        perror("Error creating socket");
        return -1;
    default:
        break;
    }
    int enable = 1;
    switch (setsockopt(sock, IPPROTO_IP, IP_HDRINCL, &enable, sizeof(enable)))
    {
    case -1:
        perror("Error setting socket options");
        return -1;
    default:
        break;
    }
    int bytes_sent = sendto(sock, reply, length, 0, (struct sockaddr *)&dest, sizeof(dest));
    switch (bytes_sent)
    {
    case -1:
        perror("Error sending reply");
        return -1;
    default:
        break;
    }
    printf("Reply sent successfully\n");
    close(sock);
    return bytes_sent;
}

char *netInterfaceSelect_spoofer(char *ebuffer, pcap_t *handle)
{
    int packets_number = 1, n;
    pcap_if_t *alldevsp, *device;
    char *devs[100][100];

    printf("Finding available devices ... ");
    int result = pcap_findalldevs(&alldevsp, ebuffer);
    switch (result)
    {
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
    while (device != NULL)
    {
        printf("%d. %s - %s\n", packets_number, device->name, device->description);
        if (device->name != NULL)
        {
            strcpy(devs[packets_number], device->name);
        }
        packets_number++;
        device = device->next;
    }

    // Ask user which device to sniff
    printf("Enter the number of the device you want to sniff : ");
    scanf("%d", &n);
    if (handle == NULL)
    {
        fprintf(stderr, "Couldn't open device %s : %s\n", devs[n], ebuffer);
        return 1;
    }
    printf("Done\n");
    char *devName = devs[n];
    return devName;
}

// Compute checksum (RFC 1071).
unsigned short calculate_checksum(unsigned short *paddress, int len)
{
    unsigned short *w = paddress;
    int nleft = len;
    int sum = 0;
    unsigned short tmp = 0;

    while (nleft > 1)
    {
        sum += *w++;
        nleft -= 2;
    }

    if (nleft == 1)
    {
        *((unsigned char *)&tmp) = *((unsigned char *)w);
        sum += tmp;
    }

    // add back carry outs from top 16 bits to low 16 bits
    sum = (sum >> 16) + (sum & 0xffff); // add hi 16 to low 16
    sum += (sum >> 16);                 // add carry
    tmp = ~sum;                         // truncate to 16 bits

    return tmp;
};

void catchNReplay(struct sockaddr_in dest, const char *packet, int ether_header_len, int packet_len, struct iphdr *IPHeader)
{
    printf("Caught ICMP echo request to %s\n", inet_ntoa(dest.sin_addr));
    char *reply = allocate_reply_packet(packet, ether_header_len, packet_len);
    create_reply_packet(packet, ether_header_len, packet_len, reply);
    dest.sin_family = AF_INET;
    int bytes_sent = send_reply(reply, packet_len - ether_header_len, dest);
    if (bytes_sent == -1)
    {
        printf("Error sending reply\n");
    }
    else
    {
        printf("Sent reply: %d bytes\n", bytes_sent);
    }
}

int open_sniffing_device(char *device_name, char *error_buffer, pcap_t **handle)
{
    printf("Opening device %s for sniffing...\n", device_name);
    *handle = pcap_open_live(device_name, 65536, 1, 1, error_buffer);
    if (*handle == NULL)
    {
        fprintf(stderr, "Error opening device %s: %s\n", device_name, error_buffer);
        return 2;
    }
    printf("Device %s opened successfully\n", device_name);
    return 0;
}

int set_filter(pcap_t *handle, char *filter_exp, bpf_u_int32 net, struct bpf_program fp)
{
    int err = pcap_compile(handle, &fp, filter_exp, 0, net);
    if (err != 0)
    {
        fprintf(stderr, "Error compiling filter: %s\n", pcap_geterr(handle));
        return 1;
    }
    err = pcap_setfilter(handle, &fp);
    if (err != 0)
    {
        fprintf(stderr, "Error setting filter: %s\n", pcap_geterr(handle));
        return 2;
    }
    printf("Filter successfully set, starting sniffing...\n");
    return 0;
}

char *allocate_reply_packet(const u_char *packet, int etherHeader, int length)
{
    // allocate memory for the reply packet
    char *reply = (char *)malloc(length - etherHeader);
    return reply;
}

void copy_headers(const u_char *packet, int ether_header_len, char *reply)
{
    struct iphdr *original_ip_header = (struct iphdr *)(packet + ether_header_len);
    struct icmphdr *original_icmp_header = (struct icmphdr *)(packet + ether_header_len + sizeof(struct iphdr));

    struct iphdr *reply_ip_header = (struct iphdr *)reply;
    struct icmphdr *reply_icmp_header = (struct icmphdr *)(reply + sizeof(struct iphdr));

    // copy the ip header from the packet we want to reply to
    memcpy(reply_ip_header, original_ip_header, sizeof(struct iphdr));
    reply_ip_header->saddr = "8.8.8.8"; // change source address
    reply_ip_header->daddr = "2.2.2.2"; // change destination address

    // copy the icmp header from the packet we want to reply to
    memcpy(reply_icmp_header, original_icmp_header, sizeof(struct icmphdr));
    reply_icmp_header->type = ICMP_ECHOREPLY; // change type to ICMP_ECHOREPLY for echo reply
    reply_icmp_header->code = 0;              // change code to 0 for echo reply
    reply_icmp_header->checksum = 0;          // reset the checksum
}

void copy_data(const u_char *packet, int ether_header_len, int packet_len, char *reply)
{
    copy_headers(packet, ether_header_len, reply);
    char *original_data = (char *)(packet + ether_header_len + sizeof(struct iphdr) + sizeof(struct icmphdr));
    int data_len = packet_len - ether_header_len - sizeof(struct iphdr) - sizeof(struct icmphdr);
    char *reply_data = (char *)(reply + sizeof(struct iphdr) + sizeof(struct icmphdr));

    if (data_len > 0)
    {
        // copy the data from the packet we want to reply to
        memcpy(reply_data, original_data, data_len);
    }
}

void create_reply_packet(const u_char *packet, int etherHeader, int length, char *reply)
{
    copy_data(packet, etherHeader, length, reply);
    struct icmphdr *ICMPHeader_reply = (struct icmphdr *)(reply + sizeof(struct iphdr));
    int dataLen = length - etherHeader - sizeof(struct iphdr) - sizeof(struct icmphdr);
    ICMPHeader_reply->checksum = calculate_checksum((unsigned short *)ICMPHeader_reply, sizeof(struct icmphdr) + dataLen);
}