#include <pcap.h>
#include <stdio.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <linux/if_ether.h>
#include <stdlib.h>

int main(int argc, char *argv[]) {
    printf("Hello");
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle;
    const unsigned char *packet;
    struct pcap_pkthdr header;
    struct iphdr *ip_header;
    int packet_count = 0;
    const int MAX_OCTET_VAL = 256; // set the constant MAX_OCTET_VALUE to be 255 (8 bits of numbers)

    int *ip_octet_counts = calloc(MAX_OCTET_VAL, sizeof(int)); // array of octet counts to count for each index


    if (argc != 2) {
        fprintf(stderr, "Usage: %s <pcap file>\n", argv[0]);
        return 1;
    }

    handle = pcap_open_offline(argv[1], errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Error opening pcap file: %s\n", errbuf);
        return 1;
    }

    while ((packet = pcap_next(handle, &header)) != NULL) {
        ip_header = (struct iphdr*)(packet + sizeof(struct ethhdr));

        uint32_t ip_addr = ntohl(ip_header->daddr); // translate network byte order to host long byte order to do bit wise operations
        int last_octet = ip_addr & 0xFF; // & bit wise operation to get last 8 bits of ip_address which is the last octet (octet values range from 0-255 so 8 bits needed only) 
        ip_octet_counts[last_octet] += 1; // just increment associated index in int array by 1 to count it
    }

    // go through whole array to just print the counts
    for (int i = 0; i < MAX_OCTET_VAL; i++) {
        printf("Last octet %d: %d\n", i, ip_octet_counts[i]);
    }

    // pcap_close(handle);
    return 0;
}
