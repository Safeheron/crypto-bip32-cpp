cmake_minimum_required(VERSION 3.10)

project("CryptoBIP32" LANGUAGES CXX VERSION 1.0.1)

add_subdirectory(src)

enable_testing()
add_subdirectory(test)

include("cmake/setup_installation.cmake")
