#pragma once
#include <arpa/inet.h>
#include "ip.h"

#pragma pack(push, 1)
struct IpHdr final {
    uint8_t  v_hl_;      // Version(4) + Header Length(4)
    uint8_t  tos_;       // Type of Service
    uint16_t len_;       // Total Length
    uint16_t id_;        // Identification
    uint16_t off_;       // Flags(3) + Fragment Offset(13)
    uint8_t  ttl_;       // Time to Live
    uint8_t  p_;         // Protocol
    uint16_t sum_;       // Header Checksum
    Ip       src_;       // Source IP Address
    Ip       dst_;       // Destination IP Address

    // Getter & Setter Helper
    uint8_t  version() const { return (v_hl_ & 0xF0) >> 4; }
    uint8_t  header_len() const { return v_hl_ & 0x0F; }
    uint16_t total_len() const { return ntohs(len_); }
    uint16_t id() const { return ntohs(id_); }
    uint16_t offset() const { return ntohs(off_); }
    uint8_t  ttl() const { return ttl_; }
    uint8_t  protocol() const { return p_; }
    uint16_t checksum() const { return ntohs(sum_); }

    Ip       src() const { return ntohl(src_); } // ip.h의 Ip클래스 활용
    Ip       dst() const { return ntohl(dst_); }

    // Protocol Constants (자주 쓰는 것만)
    enum: uint8_t {
        Icmp = 1,
        Tcp = 6,
        Udp = 17
    };
};
#pragma pack(pop)