#pragma once
#include "INCLUDE.h"

// ----------------------------------------------------------------------------
// Mac
// ----------------------------------------------------------------------------
struct Mac final {
    friend struct std::hash<Mac>;
	static constexpr int SIZE = 6;

	// constructor
	Mac() {}
	Mac(const Mac& r) { memcpy(this->mac_, r.mac_, SIZE); }
	Mac(const uint8_t* r) { memcpy(this->mac_, r, SIZE); }
	Mac(const std::string& r);

	// assign operator
	Mac& operator = (const Mac& r) { memcpy(this->mac_, r.mac_, SIZE); return *this; }

	// casting operator
	explicit operator uint8_t*() const { return const_cast<uint8_t*>(mac_); }
	explicit operator std::string() const;

	// comparison operator
	bool operator == (const Mac& r) const { return memcmp(mac_, r.mac_, SIZE) == 0; }
	bool operator != (const Mac& r) const { return memcmp(mac_, r.mac_, SIZE) != 0; }
	bool operator < (const Mac& r) const { return memcmp(mac_, r.mac_, SIZE) < 0; }
	bool operator > (const Mac& r) const { return memcmp(mac_, r.mac_, SIZE) > 0; }
	bool operator <= (const Mac& r) const { return memcmp(mac_, r.mac_, SIZE) <= 0; }
	bool operator >= (const Mac& r) const { return memcmp(mac_, r.mac_, SIZE) >= 0; }
	bool operator == (const uint8_t* r) const { return memcmp(mac_, r, SIZE) == 0; }

	void clear() {
		*this = nullMac();
	}

	bool isNull() const {
		return *this == nullMac();
	}

	bool isBroadcast() const { // FF:FF:FF:FF:FF:FF
		return *this == broadcastMac();
	}

	bool isMulticast() const { // 01:00:5E:0*
		return mac_[0] == 0x01 && mac_[1] == 0x00 && mac_[2] == 0x5E && (mac_[3] & 0x80) == 0x00;
	}

	static Mac randomMac();
	static Mac& nullMac();
	static Mac& broadcastMac();

    //utility functions
    static Mac& getMyMac(const std::string&);
    static Mac& getTargetMac(const std::string&);
    Mac& getSenderMac(const std::string&);

protected:
	uint8_t mac_[SIZE];
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