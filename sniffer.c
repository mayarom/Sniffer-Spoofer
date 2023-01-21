

/*
* Sniffer.c
*
written by Maya Rom & Yogev Ofir
id's: 207485251 & 322719881
date: 01/2023
*/

// library
#include "libsniffspoof.h"

// define the global variables
int packets_number = 1; // order number of the packet (starts from 1)
FILE *log = NULL;       // log file- will be opened in the main function

/* Main function:
the main steps:
* get the device name from the user
* open the device for sniffing
* get the filter from the user
* compile the filter
* set the filter
* open the log file
* sniff the packets
* close the log file
* close the device
*/

int main()
{

  // declare the variables
  pcap_t *handle;
  char ebuffer[PCAP_ERRBUF_SIZE];
  struct bpf_program fp;
  char *device_name = select_network_interface(ebuffer, handle); // get the device name from the user

  // Open live pcap session on NIC with name enp0s3
  printf("Opening device %s for sniffing ...\n", device_name);

  // 65536 guarantees that the whole packet will be captured on all the link layers
  handle = pcap_open_live(device_name, 65536, 1, 0, ebuffer);

  if (handle == NULL) // Check if the session is opened correctly
  {
    fprintf(stderr, "Couldn't open device %s: %s\n", device_name, ebuffer);
    return (2); // return 2 means that the program failed
  }

  // declare the variables for the filter expression and the filter itself
  char *filter_exp;
  char user_filter;

  // get the filter from the user
  filter_exp = getFilter();

  bpf_u_int32 net; // The IP of our sniffing device

  // compile the filter expression-
  // check if the filter is valid and compile it to BPF code (bytecode) that the kernel can use

  // Compile and set the filter
  if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1)
  { // compile the filter expression
    fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
    print_error("Error - Couldn't parse filter, check the filter expression\n");
    return exit_program;
  }
  if (pcap_setfilter(handle, &fp) == -1)
  { // set the filter for the session we opened in step 1
    fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(handle));
    print_error("Error - Couldn't install filter, check the filter expression\n");
    pcap_freecode(&fp); // free the memory allocated by pcap_compile
    return exit_program;
  }
  pcap_freecode(&fp); // free the memory allocated by pcap_compile

  // Open the log file to write the packets data
  log = fopen("207485251_322719881.txt", "w");
  if (log == NULL) // check if the file was opened correctly
  {
    perror("Error opening file");
    return EXIT_FAILURE; // error
  }
  // Communicate with the filter driver
  printf("start sniffing...\n");
  int ret_code = 0;
  // Capture packets - the function pcap_loop() is called to capture packets from the network
  int loop = pcap_loop(handle, -1, got_packet, NULL);
  if (loop < 0)
  {
    fprintf(stderr, "Error while capturing packets: %s\n", pcap_geterr(handle));
    ret_code = -1;
  }
  else
  { // if the capture was successful
    printf("capturing completed successfully\n");
  }
  pcap_close(handle); // Close the handle
  fclose(log);
  return ret_code; // return the return code
}

/**
 * cast_to_hex - Print data buffer in hex format to a file
 * @fp: File pointer
 * @data: Data buffer
 * @size: Size of buffer
 * Prints each byte of the data buffer in hex format to the file,
 * returns if file pointer or data is invalid.
 */

void cast_to_hex(FILE *fp, char *data, int size)
{
  // Check if the input file pointer and data buffer are valid
  if (fp == NULL || data == NULL)
  {
    // Print error message to stderr
    fprintf(stderr, "Invalid input\n");
    return;
  }
  // Check if the size of the buffer is valid
  if (size <= 0)
  {
    fprintf(stderr, "Invalid size\n");
    return;
  }

  int i; // Loop counter- index of the byte in the buffer data
  for (i = 0; i < size; i++)
  {
    // Print each byte in hex format to the file
    fprintf(fp, "%02x ", (unsigned char)data[i]); // %02x - print the byte in hex format with leading zeros
    if ((i + 1) % 16 == 0)                        // check if the current byte is the last byte of the 16 bytes' block
    {
      fprintf(fp, "\n"); // add a newline at the end of the 16 bytes' block
    }
  }
  // Add a newline character at the end
  fprintf(fp, "\n");
}

/*
 * got_packet() - Function to process a captured packet.
 *
 * @args: User-defined argument passed to the callback function.
 * @header: Pointer to the pcap_pkthdr struct containing packet metadata.
 * @packet: Pointer to the buffer containing the raw packet data.
 */
void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{
  // Get the length of the packet
  int length = header->len;

  // Cast the packet to an ethernet header struct
  struct ethhdr *eth = (struct ethhdr *)packet;

  // Get the size of the ethernet header
  int ethernet_header = sizeof(struct ethhdr) + 2;

  printf("Packet number:  %d " packets_number);
  //  if the file was not opened in the main function -Open the log file to write the packets data
  if (log == NULL)
  {
    log = fopen("207485251_322719881.txt", "w");
  }

  fprintf(log, "-------------- *** Packet number %d Size: %d *** --------------\n", packets_number++, length);
  fflush(log); // flush the log file buffer- write the data to the file immediately

  // Extract the IP header
  struct iphdr *iph = (struct iphdr *)(packet + ethernet_header);

  fprintf(log, "_____________________ ** IP **_____________________\n");
  fflush(log); // flush the log file buffer- write the data to the file immediately

  // Print the source and destination IP addresses
  struct sockaddr_in source, dest;
  memset(&source, 0, sizeof(source));
  source.sin_addr.s_addr = iph->saddr;
  memset(&dest, 0, sizeof(dest));
  dest.sin_addr.s_addr = iph->daddr;

  fprintf(log, "| source ip: %s | dest ip: %s |\n", inet_ntoa(source.sin_addr), inet_ntoa(dest.sin_addr));
  fflush(log); // flush the log file buffer- write the data to the file immediately
  // flush the log file buffer
  fflush(log); // flush the log file buffer- write the data to the file immediately
  // Check the protocol and call the appropriate function to process the packet
  if (iph->protocol == 6)
  {
    TCP_pack(packet, ethernet_header, length);
  }
  else if (iph->protocol == 1)
  {
    ICMP_pack(packet, ethernet_header, length);
  }
  else
  {
    printf("not tcp or icmp\n");
  }
}
/**
 * This function is used to process TCP packets and print relevant information to a log file.
 *
 * @param packet A pointer to the buffer containing the raw packet data.
 * @param ethernet_header Size of the ethernet header in bytes.
 * @param length Total length of the packet in bytes.
 */
void TCP_pack(const u_char *packet, int ethernet_header, int length)
{
  fprintf(log, "_____________________** TCP ** _____________________\n");

  // extract TCP header
  struct tcphdr *tcph = (struct tcphdr *)(packet + sizeof(struct iphdr) + ethernet_header);
  fprintf(log, "| source port: %u | dest port: %u |\n", ntohs(tcph->source), ntohs(tcph->dest));
  fprintf(log, "_____________________** PROTOCOL ** _____________________\n");
  // extract myHeader
  struct myHeader *my = (struct myHeader *)(packet + ethernet_header + sizeof(struct iphdr) + sizeof(struct tcphdr));
  print_time(log);
  fprintf(log, "| total_length:\t%u |\n", ntohs(my->total_lenght));
  fprintf(log, "| cache_flag:\t\t%d |\n", my->cache_flag);
  fprintf(log, "| steps_flag:\t\t%d |\n", my->steps_flag);
  fprintf(log, "| type_flag:\t\t%d |\n", my->type_flag);
  fprintf(log, "| status_code:\t\t%u |\n", ntohs(my->status_code));
  fprintf(log, "| cache_control:\t%u |\n", ntohs(my->cache_control));

  // calculate data size
  int dataSize = length - ethernet_header - sizeof(struct iphdr) - sizeof(struct tcphdr) - sizeof(struct myHeader);
  if (dataSize > 0)
  {
    fprintf(log, "_____________________data_____________________\n");
    char *data = (char *)(packet + ethernet_header + sizeof(struct iphdr) + sizeof(struct tcphdr) + sizeof(struct myHeader));
    cast_to_hex(log, data, dataSize);
    fflush(log);
  }
  fprintf(log, "\n\n");
  fflush(log);
}

/**
 * This function is used to process ICMP packets and print relevant information to a log file.
 *
 * @param packet A pointer to the buffer containing the raw packet data.
 * @param ethernet_header Size of the ethernet header in bytes.
 * @param length Total length of the packet in bytes.
 */

void ICMP_pack(const u_char *packet, int ethernet_header, int length)
{
  // extract ICMP header and print relevant information
  fprintf(log, "_____________________ ** ICMP ** _____________________\n");
  struct icmphdr *icmph = (struct icmphdr *)(packet + ethernet_header + sizeof(struct iphdr));
  fprintf(log, "|-Type:\t\t\t%d", (unsigned int)(icmph->type));

  // start count the time and add it to the packet
  print_time(log);

  // Use a switch statement to handle different ICMP types
  fprintf(log, "\n|-Message:\t\t");
  switch ((unsigned int)(icmph->type))
  {
  case 11: // ICMP Time Exceeded message
    fprintf(log, "TTL Expired");
    break;
  case ICMP_ECHOREPLY: // ICMP Echo Reply message
    fprintf(log, "ICMP Echo Reply");
    break;
  default: // Other ICMP Type
    fprintf(log, "Other ICMP Type");
    break;
  }
  fprintf(log, "\n");

  fprintf(log, "|-Code:\t\t\t%d\n", (unsigned int)(icmph->code));
  fprintf(log, "|-Checksum:\t\t%d\n", ntohs(icmph->checksum));
  fprintf(log, "|-Size:\t\t\t%ld\n", sizeof(struct icmphdr));

  // calculate data size
  int dataSize = length - ethernet_header - sizeof(struct iphdr) - sizeof(struct icmphdr);

  // if there is data, print it to the log file
  if (dataSize > 0)
  {
    fprintf(log, "_____________________ ** DATA ** _____________________\n");
    char *data = (char *)(packet + ethernet_header + sizeof(struct iphdr) + sizeof(struct icmphdr));
    cast_to_hex(log, data, dataSize);
    fprintf(log, "|-Size:\t\t\t%d\n", dataSize);
    fprintf(log, "\n\n");
    fflush(log); // flush the log file buffer- write the data to the file immediately
  }
}

// Find the available devices
/**
 * This function is used to find the available network interfaces using the pcap library.
 * @param alldevsp A pointer to a pcap_if_t struct that will be used to store the available devices.
 * @param ebuffer A pointer to a buffer that will contain error messages.
 * @return void
 */

void find_devices(pcap_if_t *alldevsp, char *ebuffer)
{
  char(*devs)[100] = malloc(100 * sizeof(*devs)); // Array to store the available devices

  printf("Finding available devices ... ");

  if (alldevsp == NULL)
  {
    print_error("No devices found");
  }
  else // if devices are found
    printf("Great! we find the devices. ");

  // Print the available devices using a loop and store the device names in the array
  printf("available Devices are :\n");

  for (pcap_if_t *device = alldevsp; device != NULL; device = device->next)
  {
    ++packets_number;
    printf("%d. %s - %s\n", packets_number, device->name, device->description);
    // check if the device name is not null and copy it to the array
    // if the device name is null , copy NULL to the array
    if (device->name != NULL)
    {
      strcpy(devs[packets_number], device->name);
    }
    else
    {
      printf("device name is null\n");
      strcpy(devs[packets_number], "NULL");
    }
  }
}

/**
 * This function is used to select a network interface to capture packets on using the pcap library.
 * @param packets_number The number of available devices.
 * @param n A pointer to an integer that will be used to store the index of the selected device in the array.
 * @return void
 */

void select_device(int packets_number, int *n)
{
  char input[100];
  while (1)
  {
    printf("Enter the number of the device you want to sniff : ");
    if (fgets(input, sizeof(input), stdin) != NULL) // get the input from the user
    {
      if (input[0] == '\n' || input[0] == ' ')
      {
        printf("Invalid input, please enter a valid number within the range of available interfaces\n");
        continue;
      }
      if (sscanf(input, "%d", n) == 1) // check if the input is an integer
      {
        if (*n > 0 && *n <= packets_number) // check if the input is in the range of the available devices
        {
          break; // break the loop if the input is valid
        }
      }
      print_error(2);
    }
    else
    {
      print_error(3);
    }
  }
}
// Open the selected device
/**
 * This function is used to open the selected device using the pcap library.
 * @param devs An array containing the names of the available devices.
 * @param n The index of the selected device in the array.
 * @param ebuffer A pointer to a buffer that will contain error messages.
 * @return A pointer to a pcap_t struct that will be used to store the handle to the selected interface.
 */
pcap_t *open_selected_device(char *devs[], int n, char *ebuffer)
{
  pcap_t *handle = pcap_open_live(devs[n], BUFSIZ, 1, 1000, ebuffer);
  if (handle == NULL)
  {
    fprintf(stderr, "Couldn't open device %s : %s\n", devs[n], ebuffer);
    return NULL;
  }
  printf("Great! we open the device %s successfully");
  return handle; // return the handle to the selected interface
}

// Main wrapper function
/**
 * This function is used to select the network interface to sniff on.
 * @param ebuffer A pointer to a buffer that will contain error messages.
 * @param handle A pointer to a pcap_t struct that will be used to store the handle to the selected interface.
 * @return A pointer to a string containing the name of the selected interface.
 */

char *select_network_interface(char *ebuffer, pcap_t *handle)
{
  // Find the available devices
  pcap_if_t *alldevsp;
  if (pcap_findalldevs(&alldevsp, ebuffer) == -1)
  {
    fprintf(stderr, "Error finding devices: %s\n", ebuffer);
    return NULL;
  }

  // Print the available devices and store their names in an array
  int packets_number = 1;
  char(*devs)[100] = malloc(100 * sizeof(*devs));
  for (pcap_if_t *device = alldevsp; device != NULL; device = device->next)
  {
    printf("%d. %s - %s\n", packets_number, device->name, device->description);
    if (device->name != NULL)
    {
      strcpy(devs[packets_number], device->name);
    }
    else
    {
      printf("device name is null\n");
      strcpy(devs[packets_number], "NULL");
    }
    packets_number++;
  }

  // Select the device
  int n;
  select_device(packets_number, &n);

  // Open the selected device
  handle = pcap_open_live(devs[n], 65536, 1, 0, ebuffer);
  if (handle == NULL)
  {
    fprintf(stderr, "Error opening device %s: %s\n", devs[n], ebuffer);
    return NULL;
  }

  char *device_name = malloc(sizeof(devs[n]));
  strcpy(device_name, devs[n]);
  free(devs);
  pcap_freealldevs(alldevsp);
  return device_name;
}
/**
 * this function is used to get the filter from the user
 *
 *
 */
char *getFilter()
{
  char *filter_exp;
  char user_filter;
  printf("Hey expensive user, \n Please enter 'A'/'a' to catch TCP packets or 'C'/'c' to catch ICMP packets \n it's your choice :) \n");

  // get the filter from the user - A or C - and check if the input is valid (A or C)
  while (scanf(" %c", &user_filter) != 1 || (user_filter != 'A' && user_filter != 'a' && user_filter != 'C' && user_filter != 'c'))
  {
    print_error(1);
  }

  // set the filter according to the user input
  if (user_filter == 'A' || user_filter == 'a')
  {
    filter_exp = "tcp and host 127.0.0.1";
    print_choice(1);
  }
  else if (user_filter == 'C' || user_filter == 'c')
  {
    filter_exp = "ICMP";
    print_choice(2);
  }

  return filter_exp;
}

void print_error(int error)
{
  if (error == 1)
  {
    printf("invalid input, please enter a valid letter 'A' or 'C'\n");
  }
  else if (error == 2)
  {
    printf("invalid input, please enter a valid number within the range of available interfaces\n");
  }
  else if (error == 3)
  {
    printf("invalid input");
  }
}

int exit_program()
{
  printf("Exiting program...");
  return -1;
}

// this function print the current time in hours, minutes and seconds
void print_time()
{
  time_t t = time(NULL);                                          // get the current time
  struct tm tm = *localtime(&t);                                  // convert the time to a struct tm
  printf("time : %d:%d:%d \n", tm.tm_hour, tm.tm_min, tm.tm_sec); // print the time

  fprintf(log, "time : %d:%d:%d ", tm.tm_hour, tm.tm_min, tm.tm_sec);
}

void print_choice(int choice)
{
  if (choice == 1)
  {
    printf("Filter set to catch packets from TCP\n");
  }
  if (choice == 2)
  {
    printf("Filter set to catch packets from ICMP\n");
  }
}
