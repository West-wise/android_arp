#include "Logger.h"
#include <iostream>
#include <iomanip>

Logger::Logger() = default;
Logger::~Logger() {
    stop();
}

void Logger::start() {
    if (running_) return;
    running_ = true;
    logWorker_ = std::thread(&Logger::workerThread, this);
    std::cout << "[Logger] Background thread started." << "\n";
}

void Logger::stop() {
    if (!running_) return;
    {
        std::lock_guard<std::mutex> lock(logMutex_);
        running_ = false;
    }
    logCond_.notify_all(); // 자고있는 스레드를 깨우고
    if (logWorker_.joinable()) { // 종료 가능한 상태라면
        logWorker_.join(); // 종료시킴
    }
}

void Logger::push(const PacketLog& log) {
    if (!running_) return;
    {
        std::lock_guard<std::mutex> lock(logMutex_); // 메세지를 넣기위에 잠깐 lock
        logQueue_.push(log); // 넣음
    }
    logCond_.notify_all(); // 알림
}

void Logger::workerThread() {
    while (true) {
        PacketLog log;

        // 락을 걸고 큐 확인
        std::unique_lock<std::mutex> lock(logMutex_);
        // 상태 변수를 확인 후 큐가 비어있지 않거나 스레드가 동작중이라면 대기 해제
        logCond_.wait(lock, [this]{return !logQueue_.empty() || !running_;});
        if (!running_ && logQueue_.empty()) break; // 종료 조건

        // 데이터 꺼내기
        log = logQueue_.front();
        logQueue_.pop();
        lock.unlock(); // 출력하는 동안은 락을 풀어서 메인스레드 대기 방지
        std::cout << "[TRAFFIC] "
                  << log.src.toString() << " -> " << log.dst.toString()
                  << " (" << std::dec << log.size << " bytes)" << std::endl;
    }
}