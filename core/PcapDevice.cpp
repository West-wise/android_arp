#include "PcapDevice.h"
#include <iostream>
#include <cstring>
#include "AppConfig.h"
#include "mac.h"

// 생성자
PcapDevice::PcapDevice(std::string_view interfaceName) : interfaceName_(interfaceName) {
    // 핸들 열기
    handle_ = pcap_open_live(interfaceName_.c_str(), BUFSIZ, 1, AppConfig::System::PCAP_READ_TMOUT_MS, errbuf_);
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

bool PcapDevice::setFilter(const Ip& sender, const Ip& target) {
    struct bpf_program filter;
    char buffer[256];
    std::snprintf(buffer, sizeof(buffer), "arp or (ip and host %s) or (ip and host %s)", sender.toString().c_str(), target.toString().c_str());
    int res = pcap_compile(handle_, &filter,buffer, 1, PCAP_NETMASK_UNKNOWN);
    if (res != 0) {
        std::cerr << "pcap_compile error return " << pcap_geterr(handle_) << std::endl;
        return false;
    }
    res = pcap_setfilter(handle_, &filter);
    pcap_freecode(&filter);
    if (res != 0) {
        std::cerr << "pcap_setfilter error return " << pcap_geterr(handle_) << std::endl;
        return false;
    }
    return true;
}
