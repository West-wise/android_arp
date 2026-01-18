#pragma once

#include <cstdint>
#include <string>
#include <string_view>
#include <array>
#include <functional>
#include <cstdio>
#include <iomanip>
#include <sstream>
#include <algorithm>
#include <fstream>
#include <random>
// ----------------------------------------------------------------------------
// Mac
// ----------------------------------------------------------------------------
struct Mac final {
	static constexpr int SIZE = 6;

	// constructor
	Mac() { mac_.fill(0); } // 기본 생성자: 00:00:00:00:00:00
	Mac(const uint8_t* r);

	// 명시적 생성자
	explicit Mac(const std::string_view r);

	// comparison operator
	bool operator == (const Mac& r) const { return mac_ == r.mac_;}
	bool operator != (const Mac& r) const { return mac_ != r.mac_; }
	bool operator < (const Mac& r) const { return mac_ < r.mac_; }

	// 명시적 문자열 변환 메서드
	std::string toString() const;

	// 포인터 접근 제공 (libcap등 C API 호환성용)
	const uint8_t* data() const { return mac_.data(); }

	static Mac randomMac();
	static Mac& nullMac();
	static Mac& broadcastMac();

    //utility functions
    static Mac getMyMac(const std::string_view if_name);
    static Mac& getTargetMac(const std::string&);
    Mac& getSenderMac(const std::string&);

protected:
	std::array<uint8_t, SIZE> mac_;

	// 해시 지원을 위한 friend선언 (unordered_map 등 사용시 필요함)
	friend struct std::hash<Mac>;
};

namespace std {
    template<>
    struct hash<Mac> {
        size_t operator() (const Mac& r) const {
            size_t hash_value = 0;
            for (size_t i = 0; i < Mac::SIZE; ++i) {
                hash_value = hash_value * 31 + r.mac_[i];
            }
            return hash_value;
        }
    };
}