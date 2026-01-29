#include "ip.h"
#include <arpa/inet.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <unistd.h>
#include <cstring>

namespace {
	struct SocketGuard {
		int fd;
		SocketGuard() {
			fd = socket(AF_INET, SOCK_DGRAM, 0);
			if (fd < 0) throw std::runtime_error("Socket creation failed");
		}
		~SocketGuard() {if (fd >= 0) close (fd);}
		operator int() const {return fd;}
	};
}

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

// 내 IP를 받아오는 함수
Ip Ip::getMyIp(std::string_view interfaceName) {
	SocketGuard sock;
	struct ifreq ifr;
	if (interfaceName.length() >= IFNAMSIZ) {
		throw std::invalid_argument("Interface name too long");
	}
	std::memset(&ifr, 0, sizeof(ifr));
	std::memcpy(ifr.ifr_name, interfaceName.data(), interfaceName.length()); // strncpy는 다르게 마지막에 널문자를 확실하게 붙여주기위한 memset->memcpy
	if (ioctl(sock, SIOCGIFADDR, &ifr) < 0) { // 하드웨어의 제어와 상태 정보를 얻기 위해 제공되는 함수인 ioctl을 사용, 에러 발생시 -1을 리턴한다
		throw std::runtime_error("Failed to get IP address for " + std::string(interfaceName));
	}
	// 네트워크 바이트 오더를 호스트 바이트 오더로 변경
	// ioctl에서 ifr구조체에 담은 정보에서 src_addr을 사용
	return Ip(ntohl(((struct sockaddr_in*)&ifr.ifr_addr)->sin_addr.s_addr));
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
