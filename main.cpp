#include <stdio.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <cstdint>
#include <string.h>
#include <pcap.h>
#include <libnet/libnet-macros.h>
#include <libnet/libnet-structures.h>
#include <libnet/libnet-types.h>
#include <libnet/libnet-headers.h>

#define PCAP_OPENFLAG_PROMISCUOUS   1


/**
 * @brief printHex
 * @detail Print Packet Data with Hex Format
 * @param length
 * @param packet
 */
void printHex(int length, const u_char* packet ) {

    int i=0;
    while(i<length) {
        printf("%02X ", packet[i]);

        ++i;
        if (i%8==0)
        {
            printf(" ");
        }
        if (i%16 == 0)
        {
            printf("\n");
        }
    }

    printf("\n");
}

//int main(int argc, char* argv[]) {
int main() {
    pcap_t *fp;
    char errbuf[PCAP_ERRBUF_SIZE];
    u_char packet[100];
    libnet_ethernet_hdr eth_header = {};
    libnet_ipv4_hdr* ip_header;
    char *dev = "dum0";

    dev = pcap_lookupdev(errbuf);


    if ( (fp = pcap_open_live(dev, BUFSIZ, PCAP_OPENFLAG_PROMISCUOUS, 1000, errbuf)) == NULL)
    {
        fprintf(stderr,"Unable to open the Adapter.%s is not supported by Libpcap %s", dev, errbuf);
        return 0;
    }

    //08:00:27:6d:8f:be
    eth_header.ether_dhost[0] = 0xff;
    eth_header.ether_dhost[1] = 0xff;
    eth_header.ether_dhost[2] = 0xff;
    eth_header.ether_dhost[3] = 0xff;
    eth_header.ether_dhost[4] = 0xff;
    eth_header.ether_dhost[5] = 0xff;

    eth_header.ether_shost[0] = 0x08;
    eth_header.ether_shost[1] = 0x00;
    eth_header.ether_shost[2] = 0x27;
    eth_header.ether_shost[3] = 0x6d;
    eth_header.ether_shost[4] = 0x8f;
    eth_header.ether_shost[5] = 0xbe;
    eth_header.ether_type = 0x0608;

    memcpy(packet, &eth_header, sizeof(eth_header));
    //memcpy(packet+sizeof(eth_header), &eth_header, sizeof(eth_header));

    /* Fill the rest of the packet */
    for(int i=sizeof(eth_header);i<100;i++)
    {
       packet[i]=i%256;
    }

    /* Send down the packet */
    if (pcap_sendpacket(fp, packet, 100 /* size */) != 0)
    {
        fprintf(stderr,"\nError sending the packet: \n", pcap_geterr(fp));
        return 0;
    }



    return 0;
}
