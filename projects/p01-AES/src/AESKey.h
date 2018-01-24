//
// Created by braden on 1/9/18.
//

#ifndef AESCRYPTOSYSTEM_AESKEY_H
#define AESCRYPTOSYSTEM_AESKEY_H

#include "AESDefinitions.h"

#include <cstdlib>
#include <iostream>
#include <vector>

typedef unsigned int Word;

class AESKey {

public:
    AESKey();
    AESKey(Byte* key, AESKeyMode mode);
    AESKey(std::string& key, AESKeyMode mode);
    AESKey(std::vector<Byte>& key, AESKeyMode mode);
    virtual ~AESKey();

    void setKey(Byte* key, AESKeyMode mode);
    void setKey(std::string& key, AESKeyMode mode);
    void setKey(std::vector<Byte>& key, AESKeyMode mode);

    Byte** nextScheme();
    Byte** inextScheme();

    const size_t& length();
    const AESKeyMode& mode();

    void resetSchedule();

private:

    void expand();
    Word subWord(Word w);
    Word rotWord(Word w);
    void printSchedule();
    int getSizeInBytes(AESKeyMode mode);
    Word createWord(Byte b1, Byte b2, Byte b3, Byte b4);

    AESKeyMode  _mode;
    std::vector<Byte> _value;
    std::vector<Word> _schedule;
    size_t _scheduleIndex;
    size_t _ischeduleIndex;

};


#endif //AESCRYPTOSYSTEM_AESKEY_H
