#pragma once

#include "ip.h"
#include <pcap.h>
#include <string>
#include <vector>
#include <string_view>
#include <stdexcept>

// pcap resource Manager
class PcapDevice final {
public:
    // 생성자
    explicit PcapDevice(std::string_view interfaceName);

    // 소멸자
    ~PcapDevice();

    // 복사 방지
    PcapDevice(const PcapDevice &) = delete;
    PcapDevice operator=(const PcapDevice &) = delete;

    // 소유권 이동은 허용
    PcapDevice(PcapDevice && other) noexcept;
    PcapDevice& operator=(PcapDevice && other) noexcept;

    bool sendPacket(const uint8_t *packet, size_t size);
    bool setFilter(const Ip& sender, const Ip& target);

    // 핸들접근은 허용
    pcap_t *getHandle() const {return handle_;}
    const std::string& getInterfaceName() const { return interfaceName_;}
    const std::string& getMacAddress() const { return macAddress_; }

private:
    std::string interfaceName_;
    std::string macAddress_;
    pcap_t *handle_;
    char errbuf_[PCAP_ERRBUF_SIZE];
};