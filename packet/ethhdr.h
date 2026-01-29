#pragma once
#include <arpa/inet.h>
#include "mac.h"

#pragma pack(push, 1)
struct EthHdr final {
	Mac dmac_;
	Mac smac_;
	uint16_t type_;

	// Getter : 네트워크 바이트 오더 -> 호스트 바이트 오더
	uint16_t  type() const {return ntohs(type_);}

	// Type(type_)
	enum Type: uint16_t {
		Ip4 = 0x0800,
		Arp = 0x0806,
		Ip6 = 0x86DD
	};
};
#pragma pack(pop)
