#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/udp.h>
#include <netinet/tcp.h>
#include <netinet/ip.h>
#include <net/ethernet.h>

void process_packet(u_char *, const struct pcap_pkthdr *, const u_char *);
void process_ip_packet(const u_char *, int);
void print_tcp_packet(const u_char *, int);
void print_udp_packet(const u_char *, int);

void process_live(char *);

void usage(void);
// void check_args(char *, char *);

int tcp = 0, udp = 0, total = 0;

int
main(int argc, char **argv)
{
  int opt;
  char * ni_name, * pcap_filename;

  while ((opt = getopt(argc, argv, "i:r:h")) != -1) {
    switch(opt) {
      case 'i':
        ni_name = strdup(optarg);
        process_live(ni_name);
        break;
      case 'r':
        pcap_filename = strdup(optarg);
        /*call function to process pcap_file*/
        break;
      case 'h':
      default:
        usage();
    }
  }

  free(ni_name);
  free(pcap_filename);

  return 0;
}

void
usage()
{
  printf(
    "\n"
    "Usage:\n"
    "    assign_6 -i netint_name \n"
    "    assign_6 -r pcap_filename \n"
    "    assign_6 -h \n"
  );
  printf(
    "\n"
    "Options:\n"
    "-i Network interface name (e.g., eth0)\n"
    "-r Packet capture filename (e.g., test.pcap)\n"
    "-h Display help message\n"
  );
  exit(EXIT_FAILURE);
}

void
process_live(char * netint)
{
  FILE * logfile, pcap_file;
  struct sockaddr_in src, dest;
  int i, j;

  pcap_if_t *alldevsp, *device;
  pcap_t *handle;

  char err[100], *devname, devs[100][100];
  int n, count = 1;

  if (pcap_findalldevs( &alldevsp, err )) {
    printf("Error finding devices: %s\n", err);
    exit(1);
  }

  printf("Available devices are:\n");
  for (device = alldevsp; device != NULL; device = device->next) {
    printf("%d. %s - %s\n", count, device->name, device->description);
    if (device->name != NULL) {
      strcpy(devs[count], device->name);
    }
    count++;
  }

  printf("Enter the device you want to sniff: ");
  scanf("%d", &n);
  devname = devs[n];

  printf("Opening device %s for live packet capturing...\n", devname);
  handle = pcap_open_live(devname, 65536, 1, 0, err);

  if (!handle) {
    fprintf(stderr, "Couldn't open device %s: %s\n", devname, err);
    exit(1);
  }

  pcap_loop(handle, -1, process_packet, NULL);

  return;
}

void
process_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *buffer)
{
  int size = header->len;

  //get IP header from packet
  struct iphdr *iph = (struct iphdr*)(buffer + sizeof(struct ethhdr));
  ++total;
  switch(iph->protocol) { //check protocol
    case 6: //TCP protocol
      ++tcp;
      print_tcp_packet(buffer, size);
      break;
    case 17: //UDP protocol
      ++udp;
      print_udp_packet(buffer, size);
      break;
    default:
      break;
  }
  printf("TCP: %d\tUDP: %d\tTotal: %d\n", tcp, udp, total);

}

void process_ip_packet(const u_char *ala, int la) {
  return;
}

void print_tcp_packet(const u_char *ala, int la) {
  return;
}

void print_udp_packet(const u_char *ala, int la) {
  return;
}
