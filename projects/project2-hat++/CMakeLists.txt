cmake_minimum_required(VERSION 3.9)
project(HashAttacks)

set(CMAKE_CXX_STANDARD 11)

add_subdirectory(lib)

add_executable(HashAttacks main.cpp
        SHA1Wrapper.cpp HashAttackSimulator.cpp HashAttackSimulator.h)

target_link_libraries(HashAttacks hashlibcpp)