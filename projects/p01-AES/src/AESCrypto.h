//
// Created by braden on 1/18/18.
//

#ifndef AESCRYPTOSYSTEM_AESCRYPTO_H
#define AESCRYPTOSYSTEM_AESCRYPTO_H

#include <iomanip>

#include "AESDefinitions.h"
#include "AESKey.h"
#include "EncryptedMessage.h"

class AESCrypto {
public:
    AESCrypto();
    virtual ~AESCrypto();

    void setKey(AESKey key);

    EncryptedMessage encrypt(EncryptedMessage message);
    EncryptedMessage decrypt(EncryptedMessage cipher);

private:

    AESKey _key;
    Byte _state[4][4];

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
    void invAddRoundKey();

    void printState(std::string prefix);

    void clearState();

};


#endif //AESCRYPTOSYSTEM_AESCRYPTO_H
