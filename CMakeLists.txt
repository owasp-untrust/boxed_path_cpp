# CMakeLists.txt - For building and testing the library

cmake_minimum_required(VERSION 3.14)
project(boxedpath VERSION 1.0.0 LANGUAGES CXX)

# Library
add_library(boxedpath
    src/BoxedPath.cpp
)

target_include_directories(boxedpath
    PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}/include
)

# Require C++17
target_compile_features(boxedpath PUBLIC cxx_std_17)

# Demo Executable
add_executable(demo examples/demo.cpp)
target_link_libraries(demo PRIVATE boxedpath)