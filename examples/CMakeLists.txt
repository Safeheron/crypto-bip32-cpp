cmake_minimum_required(VERSION 3.10)
project(example)

set(CMAKE_CXX_STANDARD 11)
set(CMAKE_BUILD_TYPE "Release")
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -O2")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -O2")

find_package(PkgConfig REQUIRED)
pkg_search_module(PROTOBUF REQUIRED protobuf)  # this looks for *.pc file
#set(OPENSSL_USE_STATIC_LIBS TRUE)
find_package(OpenSSL REQUIRED)
find_package(CryptoBN REQUIRED)
find_package(CryptoEncode REQUIRED)
find_package(CryptoCurve REQUIRED)
find_package(CryptoBIP32 REQUIRED)

add_executable(example example.cpp)
target_include_directories(example PUBLIC
        ${CryptoBN_INCLUDE_DIRS}
        ${CryptoCurve_INCLUDE_DIRS}
        ${CryptoBIP32_INCLUDE_DIRS}
        ${GTEST_INCLUDE_DIRS}
        ${PROTOBUF_INCLUDE_DIRS}
        )

target_link_libraries(example PUBLIC
        CryptoBN
        CryptoCurve
        CryptoBIP32
        OpenSSL::Crypto
        ${PROTOBUF_LINK_LIBRARIES}
        ${GTEST_BOTH_LIBRARIES}
        pthread )