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
enum class Mode { Broadcast, Unicast };

void usage();

Ip getMyIp(std::string_view interfaceName);
Mac get_mac(pcap_t *handle, const u_char *packet, size_t packetSize, Ip target_ip);
EthArpPacket Make_Infection_Packet(Mac attacker_mac, Mac sender_mac, Ip sender_ip, Ip target_ip, Mode mode);
EthArpPacket Make_Normal_Packet(Mac attacker_mac, Ip attacker_ip, Ip target_ip);
bool checkRecoverPacket(const EthArpPacket &packet, Ip SenderIP, Ip TargetIp, Mac TargetMac, Mac SenderMac);
bool sendPacket(pcap_t *handle, const u_char *packet, size_t packetSize);
