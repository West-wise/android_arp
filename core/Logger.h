#pragma once
#include <queue>
#include <mutex>
#include <condition_variable>
#include <thread>
#include <atomic>
#include <string>
#include "ip.h"


struct PacketLog {
    Ip src;
    Ip dst;
    uint32_t size;
};

class Logger {
public:
    Logger();
    ~Logger();
    void push(const PacketLog& log);
    void start();
    void stop();
private:
    std::queue<PacketLog> logQueue_;
    std::mutex logMutex_;
    std::condition_variable logCond_;

    std::thread logWorker_;
    std::atomic<bool> running_{false};

    void workerThread();
};