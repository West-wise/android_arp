cmake_minimum_required(VERSION 3.28)

# android 모듈을 포함합니다.
set(CMAKE_MODULE_PATH "/home/kali/Android/cmake")
include(android)

# LIBPCAP_INCLUDE_DIR 및 LIBPCAP_LIBRARY_DIR 변수를 설정합니다.
set(LIBPCAP_INCLUDE_DIR ${PCAP_LIB_DIR}/sysroot/include)
set(LIBPCAP_LIBRARY_DIR ${PCAP_LIB_DIR}/sysroot/lib)

# 소스 파일의 헤더 디렉토리 및 LIBPCAP_INCLUDE_DIR, LIBPCAP_LIBRARY_DIR을 포함합니다.
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/../header)
include_directories(${LIBPCAP_INCLUDE_DIR})
include_directories(${LIBPCAP_LIBRARY_DIR})

# 프로젝트를 정의하고 소스 파일을 추가합니다.
project(android-arp-${BIT})
add_compile_options(-g)
add_compile_options(-O2 -std=c++14)


# 소스 파일들을 변수에 저장합니다.
set(SOURCES
    ${CMAKE_CURRENT_SOURCE_DIR}/../src/arphdr.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/../src/ethhdr.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/../src/ip.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/../src/mac.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/../src/utill.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/../src/main.cpp
)

# 실행 파일을 추가합니다.
add_executable(${CMAKE_PROJECT_NAME} ${SOURCES})

# LIBPCAP_LIBRARY를 링크합니다.
target_link_libraries(${CMAKE_PROJECT_NAME} ${PCAP_LIB_DIR}/sysroot/lib/libpcap.a)

install(CODE "execute_process(COMMAND termux-elf-cleaner --api-level ${CMAKE_SYSTEM_VERSION} ${CMAKE_PROJECT_NAME})")
install(CODE "execute_process(COMMAND adb push ${CMAKE_PROJECT_NAME} /data/local/tmp)")