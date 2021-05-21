cmake_minimum_required(VERSION 3.19)
project(AuthCCLibrary)

set(CMAKE_CXX_STANDARD 17)

# conan
include(${CMAKE_BINARY_DIR}/conanbuildinfo.cmake)
conan_basic_setup()

add_executable(Main src/main.cpp include/AuthCC.h)
target_link_libraries(Main ${CONAN_LIBS})
