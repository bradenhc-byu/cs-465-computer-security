//
// Created by braden on 1/9/18.
//

#ifndef AESCRYPTOSYSTEM_AESKEY_H
#define AESCRYPTOSYSTEM_AESKEY_H

#include "AESModes.h"

#include <cstdlib>

class AESKey {

public:
    AESKey();
    virtual ~AESKey();

    AESKey(AESMode mode);
    AESKey(AESMode  mode, unsigned char* key);

    void generate(AESMode mode);
    const unsigned char& get();
    void set(unsigned char*key);

private:

    unsigned char* _key;
    AESMode  _mode;

};


#endif //AESCRYPTOSYSTEM_AESKEY_H
