#pragma pack(1)
struct arp_format {
    uint8_t send_mac[6];
    in_addr_t send_ip;
    uint8_t target_mac[6];
    in_addr_t target_ip;
};
#pragma pack(8)
