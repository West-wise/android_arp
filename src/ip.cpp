#include "ip.h"
#include <arpa/inet.h>

Ip::Ip(std::string_view r) {
	struct in_addr addr;
	if (inet_pton(AF_INET, r.data(), &addr) != 1){
		throw std::invalid_argument("Invalid IPv4 address format: " + std::string(r));
	}
	ip_ = ntohl(addr.s_addr); // 네트워크 바이트 순서를 호스트 순서로 변환하여 저장
}

std::string Ip::toString() const
{
	char buf[INET_ADDRSTRLEN];
	struct in_addr addr;
	addr.s_addr = htonl(ip_); // 호스트 순서를 다시 네트워크 순서로
	if (inet_ntop(AF_INET, &addr, buf, sizeof(buf)) == nullptr){
		return "0.0.0.0";
	}
	return std::string(buf);
}

#ifdef GTEST
#include <gtest/gtest.h>

TEST(Ip, ctorTest) {
	Ip ip1; // Ip()

	Ip ip2(0x7F000001); // Ip(const uint32_t r)

	Ip ip3("127.0.0.1"); // Ip(const std::string r);

	EXPECT_EQ(ip2, ip3);
}

TEST(Ip, castingTest) {
	Ip ip("127.0.0.1");

	uint32_t ui = ip; // operator uint32_t() const
	EXPECT_EQ(ui, 0x7F000001);

	std::string s = ip.toString(); // explicit operator std::string()

	EXPECT_EQ(s, "127.0.0.1");
}

#endif // GTEST
