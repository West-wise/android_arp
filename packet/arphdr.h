#pragma once
#include <cstdint>
#include <arpa/inet.h>
#include "mac.h"
#include "ip.h"

#pragma pack(push, 1)
struct ArpHdr final {
	uint16_t	hrd_;  // 하드웨어 타입
	uint16_t	pro_;  // 프로토콜 타입
	uint8_t		hln_;  // 하드웨어 주소 길이
	uint8_t		pln_;  // 프로토콜 주소 길이
	uint16_t	op_;   // 오퍼레이션(Request/Reply)
	Mac			smac_; // Sender Mac
	Ip			sip_;  // Sender Mac
	Mac			tmac_; // Target Mac
	Ip			tip_;  // Target IP


	uint16_t hrd() const { return ntohs(hrd_); }
	uint16_t pro() const { return ntohs(pro_); }
	uint16_t op() const { return ntohs(op_); }

	// HardwareType(hrd_)
	enum HardwareType : uint16_t {
		NETROM = 0, // from KA9Q: NET/ROM pseudo
		ETHER = 1, // Ethernet 10Mbps
		EETHER = 2, // Experimental Ethernet
		AX25 = 3, // AX.25 Level 2
		PRONET = 4, // PROnet token ring
		CHAOS = 5, // Chaosnet
		IEEE802 = 6, // IEEE 802.2 Ethernet/TR/TB
		ARCNET = 7, // ARCnet
		APPLETLK = 8, // APPLEtalk
		LANSTAR = 9, // Lanstar
		DLCI = 15, // Frame Relay DLCI
		ATM = 19, // ATM
		METRICOM = 23, // Metricom STRIP (new IANA id)
		IPSEC = 31 // IPsec tunnel
	};

	// Operation(op_)
	enum Operation : uint16_t {
		Request = 1, // req to resolve address
		Reply = 2, // resp to previous request
		RevRequest = 3, // req protocol address given hardware
		RevReply = 4, // resp giving protocol address
		InvRequest = 8, // req to identify peer
		InvReply = 9 // resp identifying peer
	};
};
#pragma pack(pop)
