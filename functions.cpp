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

void getMacAddress(char *interface, uint8_t *mac)
{
        int fd;

       struct ifreq ifr;
       //char *iface = "enp0s3";
       fd = socket(AF_INET, SOCK_DGRAM, 0);

       ifr.ifr_addr.sa_family = AF_INET;
       strncpy((char *)ifr.ifr_name , (const char *)interface , IFNAMSIZ-1);

       //ioctl(fd, SIOCGIFHWADDR, &ifr);

       close(fd);

       //uint8_t mac2[6] = {0};
       //mac = (u_char*)ifr.ifr_hwaddr.sa_data;
       memcpy(mac, (uint8_t*)ifr.ifr_hwaddr.sa_data, 6);

       //sprintf((char *)uc_Mac,(const char *)"%.2x:%.2x:%.2x:%.2x:%.2x:%.2x\n" , mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);

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
void setArpInfo(struct arp_format *ptr,  uint8_t target_mac[6], char *target_ip, uint8_t sender_mac[6], char *sender_ip)
{

    memcpy(ptr->send_mac, sender_mac, sizeof(sender_mac) );
    ptr->send_ip = inet_addr(sender_ip);
    memcpy(ptr->target_mac, target_mac, sizeof(target_mac) );
    ptr->target_ip = inet_addr(target_ip);
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
void setEther(struct libnet_ethernet_hdr *ptr, uint8_t target_mac[6], uint8_t sender_mac[6])
{

    //Set Target MAC
    memcpy(ptr->ether_dhost, target_mac, 6);
    memcpy(ptr->ether_shost, sender_mac, 6);
    ptr->ether_type = 0x0608;

}

void copyPacket(u_char *packet, libnet_ethernet_hdr *eth_header, libnet_arp_hdr *arp_header, arp_format *arp_info)
{
    //Copy Header to memory
    memcpy(&packet, &eth_header, sizeof(eth_header));
    memcpy(&packet+sizeof(eth_header), &arp_header, sizeof(arp_header));
    memcpy(&packet+sizeof(eth_header)+sizeof(arp_header), &arp_info, sizeof(arp_info));

}
