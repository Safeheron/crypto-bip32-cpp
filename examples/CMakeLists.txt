cmake_minimum_required(VERSION 3.10)
project(test)

set(CMAKE_CXX_STANDARD 11)
set(CMAKE_BUILD_TYPE "Release")
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -O2")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -O2")

find_package(PkgConfig REQUIRED)
pkg_search_module(PROTOBUF REQUIRED protobuf)  # this looks for *.pc file
include_directories(${PROTOBUF_INCLUDE_DIRS})

find_package(PkgConfig REQUIRED)
if(PkgConfig_FOUND )
    MESSAGE(STATUS "============> Found PkgConfig!")
endif(PkgConfig_FOUND )

pkg_search_module(PROTOBUF REQUIRED protobuf)  # depend on pkg-config, this looks for opencv.pc file
if(PROTOBUF_FOUND )
    message(STATUS "============> Found PROTOBUF!")
endif(PROTOBUF_FOUND )

#set(OPENSSL_USE_STATIC_LIBS TRUE)
find_package(OpenSSL REQUIRED)
if (OpenSSL_FOUND)
    message(STATUS "============> Found OpenSSL!")
endif (OpenSSL_FOUND)

find_package(CryptoBN REQUIRED)
if(CryptoBN_FOUND )
    MESSAGE(STATUS "============> Found CryptoBN!")
endif(CryptoBN_FOUND )

find_package(CryptoEncode REQUIRED)
if(CryptoEncode_FOUND )
    MESSAGE(STATUS "============> Found CryptoEncode!")
endif(CryptoEncode_FOUND )

find_package(CryptoCurve REQUIRED)
if(CryptoCurve_FOUND )
    MESSAGE(STATUS "============> Found CryptoCurve!")
endif(CryptoCurve_FOUND )

find_package(CryptoBIP32 REQUIRED)
if(CryptoBIP32_FOUND )
    MESSAGE(STATUS "============> Found CryptoBIP32!")
endif(CryptoBIP32_FOUND )

find_package(GTest REQUIRED)
if(GTest_FOUND )
    MESSAGE(STATUS "============> Found GTest!")
    message(STATUS "GTEST_INCLUDE_DIRS=${GTEST_INCLUDE_DIRS}")
    message(STATUS "GTEST_BOTH_LIBRARIES=${GTEST_BOTH_LIBRARIES}")
endif(GTest_FOUND )

add_executable(bip32-test bip32-test.cpp)
target_include_directories(bip32-test PUBLIC
        ${CryptoBN_INCLUDE_DIRS}
        ${CryptoCurve_INCLUDE_DIRS}
        ${CryptoBIP32_INCLUDE_DIRS}
        ${GTEST_INCLUDE_DIRS}
        )

target_link_libraries( bip32-test PUBLIC
        CryptoBN
        CryptoCurve
        CryptoBIP32
        OpenSSL::Crypto
        ${PROTOBUF_LINK_LIBRARIES}
        ${GTEST_BOTH_LIBRARIES}
        pthread )