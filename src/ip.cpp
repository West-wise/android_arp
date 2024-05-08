#include "../header/ip.h"
#include <cstdio>
#include <cstring>
#include <stdexcept>

Ip::Ip(const std::string r) {
	unsigned int a, b, c, d;
	int res = sscanf(r.c_str(), "%u.%u.%u.%u", &a, &b, &c, &d);
	if (res != SIZE) {
		fprintf(stderr, "Ip::Ip sscanf return %d r=%s\n", res, r.c_str());
		return;
	}
	ip_ = (a << 24) | (b << 16) | (c << 8) | d;
}

Ip::operator std::string() const {
	char buf[32]; // enough size
	sprintf(buf, "%u.%u.%u.%u",
		(ip_ & 0xFF000000) >> 24,
		(ip_ & 0x00FF0000) >> 16,
		(ip_ & 0x0000FF00) >> 8,
		(ip_ & 0x000000FF));
	return std::string(buf);
}


// Ip& Ip::GatewayIp(const std::string& if_name) {
//     char buffer[128];
//     std::string result = "";
//     FILE* pipe = popen("ip route show table 0 | grep wlan0", "r");
//     if (!pipe) throw std::runtime_error("popen() failed!");

//     try {
//         while (fgets(buffer, sizeof buffer, pipe) != NULL) {
//             result += buffer;
//         }
//     } catch (...) {
//         pclose(pipe);
//         throw;
//     }
//     pclose(pipe);

//     // Parse the gateway IP from the result string
//     std::size_t pos = result.find("default via ");
//     if (pos != std::string::npos) {
//         pos += strlen("default via ");
//         std::size_t end = result.find(' ', pos);
//         if (end != std::string::npos) {
//             std::string ip_str = result.substr(pos, end - pos);
//             return Ip(ip_str);  // Convert the string to an Ip object
//         }
//     }

//     throw std::runtime_error("Failed to parse gateway IP");
// }

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

	std::string s = std::string(ip); // explicit operator std::string()

	EXPECT_EQ(s, "127.0.0.1");
}

#endif // GTEST
