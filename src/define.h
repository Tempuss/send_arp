#ifndef DEFINE_H
#define DEFINE_H

char* getIpAddress(char *interface);
void getMacAddress(char *interface, uint8_t *mac);
void printHex(int length, const u_char* packet);
void setArpInfo(struct arp_format *ptr,  uint8_t target_mac[6], char *target_ip, uint8_t sender_mac[6], char *sender_ip);
void setArpType(struct libnet_arp_hdr *ptr, u_int16_t opcode);
void setEther(struct libnet_ethernet_hdr *ptr, uint8_t target_mac[6], uint8_t sender_mac[6]);
void copyPacket(u_char *packet, libnet_ethernet_hdr *eth_header, libnet_arp_hdr *arp_header, arp_format *arp_info);


#endif // DEFINE_H
