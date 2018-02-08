//
// Created by braden on 2/1/18.
//

#ifndef PROJECT2_HAT_SHA1WRAPPER_H
#define PROJECT2_HAT_SHA1WRAPPER_H

#include <stdlib.h>
#include <string>

#include "lib/hashlib2plus/hashlibpp.h"
#include "lib/hashlib2plus/hl_sha1wrapper.h"

class SHA1Wrapper {

public:
    SHA1Wrapper();

    virtual ~SHA1Wrapper();

    unsigned hash(std::string text, size_t bitSize);

private:

    hashwrapper *_sha1;

};


#endif //PROJECT2_HAT_SHA1WRAPPER_H
