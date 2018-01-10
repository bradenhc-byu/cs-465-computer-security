//
// Created by braden on 1/9/18.
//

#include <cstring>
#include "AESKey.h"

AESKey::AESKey() {
    this->_key = nullptr;
    this->_mode = BIT_128;
}

AESKey::~AESKey() {
    delete this->_key;
    this->_key = nullptr;
}

AESKey::AESKey(AESMode mode) {
    generate(mode);
}

AESKey::AESKey(AESMode mode, unsigned char *key) {
    this->_mode = mode;
    set(key);
}

void AESKey::generate(AESMode mode) {
    this->_mode = mode;
}

const unsigned char &AESKey::get() {
    return *this->_key;
}

void AESKey::set(unsigned char *key) {
    delete this->_key;
    std::size_t size = 0;
    if(this->_mode == BIT_128){
        size = 16;
    }
    else if(this->_mode == BIT_192){
        size = 24;
    }
    else if(this->_mode == BIT_256){
        size = 32;
    }
    this->_key = new unsigned char[size]();
    std::memcpy(this->_key, key, size);
}
