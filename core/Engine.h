#pragma once
#include "PcapDevice.h"
#include "ArpFlow.h"
#include "Logger.h"
#include <memory>
#include <thread>
#include <atomic>

class Engine {
public:
    Engine(std::string_view interfaceName, std::string_view senderIp, std::string_view targetIp);
    ~Engine();

    // 엔진 가동 (무한 루프)
    void run();

    // 강제 종료 (Signal Handler 등에서 사용)
    void stop() { running_ = false; }

private:
    std::unique_ptr<PcapDevice> pcap_; // unique_ptr를 사용해서 회수 및 소유권 관리
    std::unique_ptr<ArpFlow> arpFlow_;
    std::unique_ptr<Logger> logger_;

    std::atomic<bool> running_{true}; // 동작 확인을 위해 방해받으면 안되기때문에 원자적인 연산이 필요!

    // 주기적 감염을 위한 타이머
    std::chrono::steady_clock::time_point lastInfectionTime_;
    // IP 릴레이 로직 (간단하므로 Engine 내장)
    void relayIp(const uint8_t* packet, size_t len);
};