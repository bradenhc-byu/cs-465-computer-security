//
// Created by braden on 2/1/18.
//

#include "SHA1Wrapper.h"
#include <iostream>

SHA1Wrapper::SHA1Wrapper() {
    _sha1 = new sha1wrapper();
}

SHA1Wrapper::~SHA1Wrapper() {
    delete _sha1;
}

unsigned int SHA1Wrapper::hash(std::string text, size_t bitSize) {
    try{
        std::string hexString = _sha1->getHashFromString(text).substr(0,8);
        size_t shift = hexString.length() * 4 - bitSize;
        auto result = (unsigned int) std::strtol(hexString.c_str(), 0, 16);
        return result >> shift;
    }
    catch(hlException &e){
        std::cerr << e.error_message() << std::endl;
    }
}
