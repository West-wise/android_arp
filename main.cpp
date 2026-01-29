#include "core/Engine.h"
#include <iostream>
#include <csignal>
#include <memory>

std::unique_ptr<Engine> engine = nullptr;
volatile std::sig_atomic_t flag = 0;
void signalHandler(int signum) {
        (void)signum; // 경고 방지
        flag = 1;
        if (engine) {
                engine->stop();
        }
}

int main(int argc, char* argv[]) {
        if (argc != 4) {
                std::cerr << "Usage: " << argv[0] << " <interface> <sender_ip> <target_ip>" << std::endl;
                return -1;
        }
        std::signal(SIGINT, signalHandler);
        try {
                engine = std::make_unique<Engine>(argv[1], argv[2], argv[3]);
                engine->run();
        }
        catch (const std::exception& e) {
                std::cerr << "[Fatal Error] " << e.what() << std::endl;
                return -1;
        }

        // engine 포인터가 스코프를 벗어나면서 소멸자 호출 -> recover() 자동 실행
        std::cout << "[Main] Byte." << std::endl;
        return 0;
}