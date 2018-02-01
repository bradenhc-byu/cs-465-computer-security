//
// Created by braden on 1/9/18.
//

#include <cstring>
#include <iomanip>
#include "AESKey.h"

AESKey::AESKey() = default;

AESKey::AESKey(Byte *key, AESKeyMode mode) {
    setKey(key, mode);
}

AESKey::AESKey(std::string& key, AESKeyMode mode) {
    setKey(key, mode);
}

AESKey::AESKey(std::vector<Byte>& key, AESKeyMode mode) {
    setKey(key, mode);
}

AESKey::~AESKey() = default;

void AESKey::setKey(Byte *key, AESKeyMode mode) {
    _mode = mode;
    int size = getSizeInBytes(mode);
    _value.clear();
    for(int i = 0; i < size; i++){
        _value.push_back(key[i]);
    }
    expand();
}

void AESKey::setKey(std::string& key, AESKeyMode mode) {
    _mode = mode;
    int remaining = getSizeInBytes(mode);
    _value.clear();
    for(char c : key){
        if(remaining <= 0) break;
        _value.push_back((Byte)c);
    }
    expand();
}

void AESKey::setKey(std::vector<Byte>& key, AESKeyMode mode) {
    _mode = mode;
    int remaining = getSizeInBytes(mode);
    _value.clear();
    for(Byte b : key){
        if(remaining <= 0) break;
        _value.push_back(b);
    }
    expand();
}

Byte **AESKey::nextScheme() {
    if(_scheduleIndex >= _schedule.size()){
        return nullptr;
    }
    auto scheme = new Byte*[4];
    for(int i = 0; i < 4; i++){
        scheme[i] = new Byte[4];
    }
    for(size_t i = 0; i < 4; i++){
        scheme[0][i] = (Byte)((_schedule.at(_scheduleIndex + i) & 0xFF000000) >> 24);
        scheme[1][i] = (Byte)((_schedule.at(_scheduleIndex + i) & 0x00FF0000) >> 16);
        scheme[2][i] = (Byte)((_schedule.at(_scheduleIndex + i) & 0x0000FF00) >> 8);
        scheme[3][i] = (Byte)(_schedule.at(_scheduleIndex + i) & 0x000000FF);
    }
    _scheduleIndex += 4;

    return scheme;
}

Byte **AESKey::inextScheme() {
    if(_ischeduleIndex < 0) return nullptr;
    auto scheme = new Byte*[4];
    for(int i = 0; i < 4; i++){
        scheme[i] = new Byte[4];
    }
    for(size_t i = 0; i < 4; i++){
        scheme[0][i] = (Byte)((_schedule.at(_ischeduleIndex + i) & 0xFF000000) >> 24);
        scheme[1][i] = (Byte)((_schedule.at(_ischeduleIndex + i) & 0x00FF0000) >> 16);
        scheme[2][i] = (Byte)((_schedule.at(_ischeduleIndex + i) & 0x0000FF00) >> 8);
        scheme[3][i] = (Byte)(_schedule.at(_ischeduleIndex + i) & 0x000000FF);
    }
    _ischeduleIndex -= 4;

    return scheme;
}
const AESKeyMode &AESKey::mode() {
    return _mode;
}

int AESKey::getSizeInBytes(AESKeyMode mode) {
    switch(mode){
        case BIT_128: return 16;

        case BIT_192: return 24;

        case BIT_256: return 32;

        default: return -1;
    }
}

const size_t &AESKey::length() {
    return _value.size();
}

void AESKey::resetSchedule() {
    _scheduleIndex = 0;
    _ischeduleIndex = _schedule.size() - 4;
}

void AESKey::expand() {
    // Determine the number of AES rounds from key length
    int rounds = 0;
    switch(_mode){
        case BIT_128:
            rounds = 10;
            break;
        case BIT_192:
            rounds = 12;
            break;
        case BIT_256:
            rounds = 14;
            break;
    }

    // Set the length of the key in words
    size_t keyLengthInWords = (_value.size()) / 4;

    // Generate the first key scheme
    for(size_t i = 0; i < keyLengthInWords; i++){
        _schedule.push_back(createWord(_value.at(i*4), _value.at(i*4+1), _value.at(i*4+2), _value.at(i*4+3)));
    }

    // Generate the rest of the key
    size_t scheduleLength = 4 * (rounds + 1);
    for(size_t i = keyLengthInWords; i < scheduleLength; i++){
        Word tmp = _schedule[i - 1];
        if(i % keyLengthInWords == 0){
            tmp = subWord(rotWord(tmp)) ^ AES_RCON[i/keyLengthInWords];
        }
        else if(keyLengthInWords > 6 && i % keyLengthInWords == 4){
            tmp = subWord(tmp);
        }
        _schedule.push_back(_schedule[i - keyLengthInWords] ^ tmp);
    }
    printSchedule();
    _scheduleIndex = 0;
    _ischeduleIndex = scheduleLength - 4;
}

Word AESKey::subWord(Word w) {
    Byte b1 = AES_SBOX[(w & 0x000000F0) >> 4][(w & 0x0000000F)];
    Byte b2 = AES_SBOX[(w & 0x0000F000) >> 12][(w & 0x00000F00) >> 8];
    Byte b3 = AES_SBOX[(w & 0x00F00000) >> 20][(w & 0x000F0000) >> 16];
    Byte b4 = AES_SBOX[(w & 0xF0000000) >> 28][(w & 0x0F000000) >> 24];
    Word nw = 0;
    return nw ^ (b4 << 24) ^ (b3 << 16) ^ (b2 << 8) ^ b1;
}

Word AESKey::rotWord(Word w) {
    Word first = w >> 24;
    w <<= 8;
    return w ^ first;
}

void AESKey::printSchedule() {
    std::cout << "Key Schedule for AES:" << std::endl;
    int round = 0;
    int step = 4;
    for(int i = 0; i < _schedule.size(); i += step){
        std::cout << std::dec <<  "Round[" << round << "]: " << std::hex << std::setfill('0') << std::setw(2)
                  << _schedule[i] << _schedule[i+1] << _schedule[i+2] << _schedule[i+3] << std::endl;
        round++;
    }
}

Word AESKey::createWord(Byte b1, Byte b2, Byte b3, Byte b4) {
    Word w = 0;
    return  w ^ (b1 << 24) ^ (b2 << 16) ^ (b3 << 8) ^ b4;
}
