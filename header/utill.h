#pragma once
#include <pcap.h>
#include <string_view>
#include "ethhdr.h"
#include "arphdr.h"


#pragma pack(push, 1)
struct EthArpPacket final
{
    EthHdr eth_;
    ArpHdr arp_;
};
#pragma pack(pop)

void usage();

void print_info(struct libnet_ipv4_hdr *header,
                u_int8_t *m,
                u_int8_t *m2);

EthArpPacket Sender_Infection(char *interfaceName, Mac my_mac, Mac SenderMac, Ip sip, Ip tip);
EthArpPacket Target_Infection(char *interfaceName, Mac my_mac, Mac SenderMac, Ip sip, Ip tip);
EthArpPacket One_Infection(char *interfaceName, Mac my_mac, Mac Sender_Mac, Ip sip, Ip tip);
EthArpPacket normal_packet(char *interfaceName, Mac my_mac, Ip sip, Ip my_ip);
EthArpPacket Broadcast_Infection(char *interfaceName, Mac my_mac, Ip tip);

EthArpPacket Make_packet(char *interfaceName,
                         Mac eth_dmac,
                         Mac eth_smac,
                         Mac arp_smac,
                         Ip arp_sip,
                         Mac arp_tmac,
                         Ip arp_tip);

void check_arp_reply(u_char* param, const struct pcap_pkthdr* header, const u_char* pkt_data);
Ip getMyIp(std::string_view interfaceName);
void SendInfectionPacket(pcap_t *handle, EthArpPacket packet);
Mac get_mac(pcap_t *handle, const u_char *packet, size_t packetSize, Ip target_ip);
EthArpPacket Make_Infection_Packet(Mac attacker_mac, Mac sender_mac, Ip sender_ip, Ip target_ip);
EthArpPacket Make_Normal_Packet(Mac attacker_mac, Ip attacker_ip, Ip target_ip);