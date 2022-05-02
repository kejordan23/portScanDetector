cmake_minimum_required(VERSION 3.20)
project(portscanner)

set(CMAKE_CXX_STANDARD 14)

include(FindPCAP.cmake)

add_executable(portscanner main.cpp Parse.h)
target_link_libraries(portscanner ${PCAP_LIBRARY})
