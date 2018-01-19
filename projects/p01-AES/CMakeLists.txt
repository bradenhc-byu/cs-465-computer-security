cmake_minimum_required(VERSION 3.9)
project(AESCryptosystem)

set(CMAKE_CXX_STANDARD 11)

add_executable(AESCryptosystem
        src/AESCrypto.cpp
        src/AESKey.cpp
        src/AESDefinitions.h
        src/EncryptedMessage.cpp
        src/main.cpp)