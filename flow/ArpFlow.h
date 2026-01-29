#pragma once
#include "PcapDevice.h"
#include "mac.h"
#include "ip.h"
#include "ethhdr.h"
#include "arphdr.h"

class ArpFlow {
public:
    ArpFlow(PcapDevice *pcap, Ip sender_ip, Ip target_ip);

    void resolveMacs();
    void sendInfectionPacket();
    bool checkRecoverPacket(EthHdr *eth, ArpHdr *arp);
    Mac getSenderMac() const {return senderMac_;}
    Mac getTargetMac() const {return targetMac_;}
    Ip getSenderIp() const {return senderIp_;}
    Ip getTargetIp() const {return targetIp_;}
    void recover(); // 공격 종료시 대상 arp테이블 원복

private:
    PcapDevice *pcap_;
    Mac myMac_;
    Ip myIp_;
    Ip senderIp_;
    Mac senderMac_;
    Ip targetIp_;
    Mac targetMac_;
    void sendArpPacket(Mac dmac, Mac smac, uint16_t op, Mac arp_smac, Ip arp_sip, Mac arp_tmac, Ip arp_tip);
    Mac queryMac(Ip ip);
};