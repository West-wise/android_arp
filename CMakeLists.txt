cmake_minimum_required(VERSION 3.28)

# 1. 프로젝트 설정
# build.sh에서 넘어오는 BIT 변수(32/64)를 반영
if(NOT DEFINED BIT)
    set(BIT 64) # 기본값
endif()

# android 모듈을 포함합니다.
# set(CMAKE_MODULE_PATH "/home/kali/Android/cmake")
# include(android)

project(android-arp-${BIT} LANGUAGES CXX)

# 2. 컴파일 옵션 및 표준 설정 (Modern C++)
set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS OFF)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

add_compile_options(-g -O2 -Wall -Wextra) # 경고 레벨 상향 (전문가 스타일)

# 3. 라이브러리 및 의존성 설정 (libpcap)
# build.sh에서 설정한 환경 변수나 경로를 그대로 활용
if(DEFINED ENV{PCAP_LIB_DIR})
    set(LIBPCAP_ROOT $ENV{PCAP_LIB_DIR}/sysroot)
    include_directories(${LIBPCAP_ROOT}/include)
    link_directories(${LIBPCAP_ROOT}/lib)
else()
    message(WARNING "PCAP_LIB_DIR not defined. Assuming system default or manual path.")
endif()



# 5. 소스 파일 수집 (Source Collection)
# 각 모듈별로 소스를 명확히 분리하여 수집
file(GLOB_RECURSE SRC_CORE "core/*.cpp")
file(GLOB_RECURSE SRC_PACKET "packet/*.cpp")
file(GLOB_RECURSE SRC_FLOW "flow/*.cpp")
file(GLOB_RECURSE SRC_CONFIG "config/*.cpp") # 만약 cpp가 있다면

# 메인 진입점
set(SRC_MAIN "main.cpp")

# 6. 실행 파일 생성
add_executable(${PROJECT_NAME}
        ${SRC_MAIN}
        ${SRC_CORE}
        ${SRC_PACKET}
        ${SRC_FLOW}
        ${SRC_CONFIG}
)

# 헤더 경로 등록 (색인 핵심)
target_include_directories(${CMAKE_PROJECT_NAME}
        PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/config
        ${CMAKE_CURRENT_SOURCE_DIR}/core
        ${CMAKE_CURRENT_SOURCE_DIR}/packet
        ${CMAKE_CURRENT_SOURCE_DIR}/flow
)

# 7. 라이브러리 링크
# 정적 라이브러리(libpcap.a) 직접 링크
if(EXISTS "${LIBPCAP_ROOT}/lib/libpcap.a")
    target_link_libraries(${PROJECT_NAME} PRIVATE "${LIBPCAP_ROOT}/lib/libpcap.a")
else()
    target_link_libraries(${PROJECT_NAME} PRIVATE pcap) # 시스템 설치 버전
endif()

# 8. 설치 및 배포 (기존 유지)
# Termux 및 ADB 배포 편의성
install(CODE "execute_process(COMMAND termux-elf-cleaner --api-level ${CMAKE_SYSTEM_VERSION} ${PROJECT_NAME})")
install(CODE "execute_process(COMMAND adb push ${PROJECT_NAME} /data/local/tmp)")