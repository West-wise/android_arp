cmake_minimum_required(VERSION 3.28)

set(CMAKE_MODULE_PATH "/home/kali/Android/cmake")


include(android)

project(interface-list-${BIT})

include_directories(${PCAP_LIB_DIR}/sysroot/include)
add_executable(${CMAKE_PROJECT_NAME} interface-list.c)
target_link_libraries(${CMAKE_PROJECT_NAME} ${PCAP_LIB_DIR}/sysroot/lib/libpcap.a)


install(CODE "execute_process(COMMAND termux-elf-cleaner --api-level ${CMAKE_SYSTEM_VERSION} ${CMAKE_PROJECT_NAME})")
install(CODE "execute_process(COMMAND adb push ${CMAKE_PROJECT_NAME} /data/local/tmp)")