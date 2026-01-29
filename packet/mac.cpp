#include "mac.h"

Mac::Mac(const uint8_t* r){
	std::copy(r, r + SIZE, mac_.begin());
}

Mac::Mac(const std::string_view r){
	// 1. 구분자(:, -)를 제거하고 순수 16진수 문자만 추출
	std::string hex;
	for(char ch : r){
		if(std::isxdigit(static_cast<unsigned char>(ch))){
			hex += ch;
		}
	}
	// 2. 12글자인지 확인
	if (hex.length() != 12) {
		throw std::invalid_argument("Invalid MAC address format: " + std::string(r));
	}

	// 3. 2글자씩 끊어서 바이트로 변환
	for (int i = 0; i < SIZE; i++)
	{
		mac_[i] = static_cast<uint8_t>(std::stoul(hex.substr(i*2,2), nullptr, 16));
	}
}

std::string Mac::toString() const
{
	std::ostringstream oss;
	oss << std::hex << std::setfill('0');
	for (int i = 0; i<SIZE; i++)
	{
		oss << std::setw(2) << static_cast<int>(mac_[i]);
		if (i < SIZE - 1) oss << ":";
	}
	return oss.str();
}

Mac Mac::randomMac()
{
	Mac res;
	std::random_device rd;
	std::mt19937 gen(rd());
	std::uniform_int_distribution<> dis(0, 255);

	for (int i = 0; i < SIZE; i++)
	{
		res.mac_[i] = static_cast<uint8_t>(dis(gen));
	}
	res.mac_[0] &= 0xFE;
	return res;
}

Mac& Mac::nullMac()
{
	static Mac res;
	return res;
}

Mac& Mac::broadcastMac() {
	static uint8_t _value[] = { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF };
	static Mac res(_value);
	return res;
}

Mac Mac::getMyMac(const std::string_view if_name) {
    std::ifstream iface("/sys/class/net/" + std::string(if_name) + "/address");
	if (!iface.is_open())
	{
		throw std::runtime_error("Failed to open interface: " + std::string(if_name));
	}
	std::string str;
	iface >> str;
	return Mac(str);
}

// ----------------------------------------------------------------------------
// GTEST
// ----------------------------------------------------------------------------
#ifdef GTEST
#include <gtest/gtest.h>

static constexpr uint8_t _temp[] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55};

TEST(Mac, ctorTest) {
	Mac mac1; // ()

	Mac mac2{mac1}; // (const Mac& r)

	Mac mac3(_temp); // (const uint8_t* r)

	Mac mac4(std::string("001122-334455")); // (const std::string& r)
	EXPECT_EQ(mac3, mac4);

	Mac mac5("001122-334455"); // (const std::string& r)
	EXPECT_EQ(mac3, mac5);
}

TEST(Mac, castingTest) {
	Mac mac("001122-334455");

	const uint8_t* uc = (uint8_t*)mac; // operator uint8_t*()
	uint8_t temp[Mac::SIZE];
	for (int i = 0; i < Mac::SIZE; i++)
		temp[i] = *uc++;
	EXPECT_TRUE(memcmp(&mac, temp, 6) == 0);

	std::string s2 = std::string(mac); // operator std::string()
	EXPECT_EQ(s2, "00:11:22:33:44:55");
}

TEST(Mac, funcTest) {
	Mac mac;

	mac.clear();
	EXPECT_TRUE(mac.isNull());

	mac = std::string("FF:FF:FF:FF:FF:FF");
	EXPECT_TRUE(mac.isBroadcast());

	mac = std::string("01:00:5E:00:11:22");
	EXPECT_TRUE(mac.isMulticast());
}

#include <map>
TEST(Mac, mapTest) {
	typedef std::map<Mac, int> MacMap;
	MacMap m;
	m.insert(std::make_pair(Mac("001122-334455"), 1));
	m.insert(std::make_pair(Mac("001122-334456"), 2));
	m.insert(std::make_pair(Mac("001122-334457"), 3));
	EXPECT_EQ(m.size(), 3);
	MacMap::iterator it = m.begin();
	EXPECT_EQ(it->second, 1); it++;
	EXPECT_EQ(it->second, 2); it++;
	EXPECT_EQ(it->second, 3);
}

#include <unordered_map>
TEST(Mac, unordered_mapTest) {
	typedef std::unordered_map<Mac, int> MacUnorderedMap;
	MacUnorderedMap m;
	m.insert(std::make_pair(Mac("001122-334455"), 1));
	m.insert(std::make_pair(Mac("001122-334456"), 2));
	m.insert(std::make_pair(Mac("001122-334457"), 3));
	//EXPECT_EQ(m.size(), 3);
}

#endif // GTEST