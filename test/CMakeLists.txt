cmake_minimum_required(VERSION 3.10)
project(test)

find_package(GTest REQUIRED)
include_directories(${GTEST_INCLUDE_DIRS})

find_package(PkgConfig REQUIRED)
pkg_search_module(PROTOBUF REQUIRED protobuf)  # this looks for opencv.pc file

set(CMAKE_CXX_STANDARD 11)
#set(CMAKE_BUILD_TYPE "Release")
#set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -O2")
#set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -O2")
SET(CMAKE_BUILD_TYPE "Debug")

find_package(GTest REQUIRED)
if(GTest_FOUND )
    MESSAGE(STATUS "============> Found GTest!")
    message(STATUS "GTEST_INCLUDE_DIRS=${GTEST_INCLUDE_DIRS}")
    message(STATUS "GTEST_BOTH_LIBRARIES=${GTEST_BOTH_LIBRARIES}")
endif(GTest_FOUND )

include_directories("../src")

add_executable(bip32-test bip32-test.cpp)
target_link_libraries( bip32-test
        CryptoBIP32
        ${GTEST_BOTH_LIBRARIES}
        pthread )
add_test(NAME test-bip32 COMMAND bip32-test)