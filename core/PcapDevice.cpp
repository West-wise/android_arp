#include "PcapDevice.h"
#include <iostream>
#include <cstring>
#include "mac.h"

// 생성자
PcapDevice::PcapDevice(std::string_view interfaceName) : interfaceName_(interfaceName) {
    // 핸들 열기
    handle_ = pcap_open_live(interfaceName_.c_str(), BUFSIZ, 1, 1, errbuf_);
    if (handle_ == nullptr) throw std::runtime_error("Couldn't open device " + interfaceName_ + ": " + std::string(errbuf_));
    // 생성자 호출 시점에 나의 Mac주소 미리 캐싱
    try {
        macAddress_ = Mac::getMyMac(interfaceName_).toString();
    } catch (...) {
        pcap_close(handle_);
        throw;
    }
}

PcapDevice::~PcapDevice() {
    if (handle_) {
        pcap_close(handle_);
        handle_ = nullptr;
    }
}

// 이동 생성자 구현
PcapDevice::PcapDevice(PcapDevice&& other) noexcept
    : interfaceName_(std::move(other.interfaceName_)),
      macAddress_(std::move(other.macAddress_)),
      handle_(other.handle_) {
    other.handle_ = nullptr;
}

PcapDevice& PcapDevice::operator=(PcapDevice&& other) noexcept {
    if (this != &other) {
        if (handle_) pcap_close(handle_);
        interfaceName_ = std::move(other.interfaceName_);
        macAddress_ = std::move(other.macAddress_);
        handle_ = other.handle_;

        other.handle_ = nullptr;
    }
    return *this;
}
bool PcapDevice::sendPacket(const uint8_t *packet, size_t size) {
    int res = pcap_sendpacket(handle_, packet, (int)size);
    if (res != 0) {
        std::cerr << "pcap_sendpacket error return " << res << " : " << pcap_geterr(handle_) << std::endl;
        return false;
    }
    return true;
}

// Mac PcapDevice::getMacAddress(){
//     // ARP request 전송
//     // ARP를 전송하면 대상은 mac주소를 반환하게 되어있음
//     if (!sendPacket(handle_, packet, packetSize)){
//         return Mac::nullMac();
//     }
//
//     // 응답을 대기, 기존의 pcap_loop는 패킷을 받는 즉시 mac주소를 얻을 수 있는 상황일 경우만 유효
//     constexpr int MAX_TRY = 50;
//     int try_cnt = 0;
//     while (try_cnt++ < MAX_TRY) {
//         struct pcap_pkthdr* header;
//         const u_char* pkt_data;
//         int res = pcap_next_ex(handle_, &header, &pkt_data);
//         if (res == 0) continue;
//         if (res == -1 || res == -2) break;
//         struct EthHdr *eh = (struct EthHdr*)pkt_data;
//         if (eh->type() != EthHdr::Arp) continue;
//         struct ArpHdr *ah = (struct ArpHdr*)((u_char*)eh + sizeof(EthHdr));
//         if (ah->op() == ArpHdr::Reply && ah->sip_ == target_ip) {
//             return ah->smac_;
//         }
//     }
//     return Mac::nullMac();
// }
