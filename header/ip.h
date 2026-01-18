#pragma once
#include <cstdint>
#include <string>
#include <stdexcept>
#include <string_view>


struct Ip final {
	static constexpr int SIZE = 4; // constexpr : 컴파일 타임 값 결정

	// constructor
	Ip() : ip_(0) {}
	Ip(const uint32_t r) : ip_(r) {}
	explicit Ip(std::string_view r);

	// casting operator
	operator uint32_t() const { return ip_; } // default

	// comparison operator
	bool operator == (const Ip& r) const { return ip_ == r.ip_; }

	bool isLocalHost() const { // 127.*.*.*
		// uint8_t prefix = (ip_ & 0xFF000000) >> 24;
		return (ip_ >> 24) == 0x7F;
	}

	bool isBroadcast() const { // 255.255.255.255
		return ip_ == 0xFFFFFFFF;
	}

	bool isMulticast() const { // 224.0.0.0 ~ 239.255.255.255
		// uint8_t prefix = (ip_ & 0xFF000000) >> 24;
		return (ip_ >> 24) >= 0xE0 && (ip_ >> 24) < 0xF0;
	}
	std::string toString() const;

protected:
	uint32_t ip_;
};
