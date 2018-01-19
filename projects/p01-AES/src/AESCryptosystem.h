//
// Created by braden on 1/9/18.
//

#ifndef P01_AES_AESCRYPTOSYSTEM_H
#define P01_AES_AESCRYPTOSYSTEM_H

#include "AESKey.h"
#include "AESModes.h"
#include "CryptoMessage.h"

#include <iostream>

class AESCryptosystem {
public:
    explicit AESCryptosystem(AESKey key);
    virtual ~AESCryptosystem();

    void setKey(AESKey key);

    CryptoMessage encrypt(CryptoMessage message);

    CryptoMessage decrypt(CryptoMessage cipher);

private:

    Byte ffadd(Byte a, Byte b);
    Byte xtime(Byte a);
    Byte ffmultiply(Byte a, Byte b);

    void subBytes();
    void shiftRows();
    void mixColumns();
    void addRoundKey();

    void invSubBytes();
    void invShiftRows();
    void invMixColumns();

    void printState(std::string prefix);


    AESKey _initialKey;
    int _rounds;
    Byte _state[4][4];
};


#endif //P01_AES_AESCRYPTOSYSTEM_H
