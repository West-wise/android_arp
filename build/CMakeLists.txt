cmake_minimum_required(VERSION 3.28)

include_directories(${CMAKE_CURRENT_SOURCE_DIR}/../header)
include_directories(${PCAP_LIB_DIR}/sysroot/include)

set(CMAKE_MODULE_PATH "/home/kali/Android/cmake")
include(android)

project(android-arp-${BIT})


set(SOURCES
    ${CMAKE_CURRENT_SOURCE_DIR}/../src/arphdr.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/../src/ethhdr.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/../src/ip.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/../src/mac.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/../src/main.cpp
)


add_executable(${CMAKE_PROJECT_NAME} ${SOURCES})
target_link_libraries(${CMAKE_PROJECT_NAME} ${PCAP_LIB_DIR}/sysroot/lib/libpcap.a)


# install(CODE "execute_process(COMMAND termux-elf-cleaner --api-level ${CMAKE_SYSTEM_VERSION} ${CMAKE_PROJECT_NAME})")
# install(CODE "execute_process(COMMAND adb push ${CMAKE_PROJECT_NAME} /data/local/tmp)")