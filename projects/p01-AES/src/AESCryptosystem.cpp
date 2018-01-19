//
// Created by braden on 1/9/18.
//

#include <sstream>
#include <iomanip>
#include "AESCryptosystem.h"

AESCryptosystem::AESCryptosystem(AESKey key) : _initialKey(key) {
    if(key.length() == AESKey::BIT_128){
        _rounds = 10;
    }
    else if(key.length() == AESKey::BIT_192){
        _rounds = 12;
    }
    else if(key.length() == AESKey::BIT_256){
        _rounds = 14;
    }
}

AESCryptosystem::~AESCryptosystem() {

}

void AESCryptosystem::setKey(AESKey key) {
    this->_initialKey = key;
    if(key.length() == AESKey::BIT_128){
        _rounds = 10;
    }
    else if(key.length() == AESKey::BIT_192){
        _rounds = 12;
    }
    else if(key.length() == AESKey::BIT_256){
        _rounds = 14;
    }
}

CryptoMessage AESCryptosystem::encrypt(CryptoMessage message) {
    CryptoMessage cipher;
    std::vector<Byte> chunk = message.nextChunk();
    while(chunk.size() != 0){
        // Generate the matrix state
        for(int i = 0; i < CryptoMessage::CHUNK_128; i++){
            _state[i % 4][i / 4] = chunk[i];
        }

        printState("round[0].input");

        // Perform AES on the state
        addRoundKey();

        for(int i = 0; i < _rounds - 1; i++){
            std::stringstream prefix;
            prefix << "round[" << i << "].";
            printState(prefix.str() + "start");
            subBytes();
            printState(prefix.str() + "s_box");
            shiftRows();
            printState(prefix.str() + "s_row");
            mixColumns();
            printState(prefix.str() + "m_col");
            addRoundKey();
        }

        subBytes();
        shiftRows();
        addRoundKey();

        // Reset the the head of the key schedule
        _initialKey.resetSchedule();

        // Convert back to a byte vector
        std::vector<Byte> newChunk(CryptoMessage::CHUNK_128, Byte());
        for(int i = 0; i < 4; i++){
            for(int j = 0; j < 4; j++){
                newChunk.push_back(_state[j][i]);
            }
        }

        // Append the result
        cipher.append(newChunk);
        chunk = message.nextChunk();
    }

    return cipher;
}

CryptoMessage AESCryptosystem::decrypt(CryptoMessage cipher) {
    CryptoMessage message;
    std::vector<Byte> chunk = cipher.nextChunk();
    while(chunk.size() != 0){
        // Generate the matrix state
        for(int i = 0; i < CryptoMessage::CHUNK_128; i++){
            _state[i / 4][i % 4] = chunk[i];
        }

        printState("round[0].input   ");

        // Perform AES on the state
        addRoundKey();

        printState("round[0].start   ");

        for(int i = 0; i < _rounds - 1; i++){
            invShiftRows();
            invSubBytes();
            addRoundKey();
            invMixColumns();
        }

        invShiftRows();
        invSubBytes();
        addRoundKey();

        // Reset the the head of the key schedule
        _initialKey.resetSchedule();

        // Convert back to a byte vector
        std::vector<Byte> newChunk(CryptoMessage::CHUNK_128, Byte());
        for(int i = 0; i < 4; i++){
            for(int j = 0; j < 4; j++){
                newChunk.push_back(_state[j][i]);
            }
        }

        // Append the result
        message.append(newChunk);
        chunk = cipher.nextChunk();
    }

    return message;
}

Byte AESCryptosystem::ffadd(Byte a, Byte b) {
    return a ^ b;
}

Byte AESCryptosystem::xtime(Byte a) {
    return (a & 0x80) ? (Byte)((a << 1) ^ 0x1B) : (Byte)(a << 1);
}

Byte AESCryptosystem::ffmultiply(Byte a, Byte b) {
    Byte result = 0;
    Byte count = 0x01;
    Byte c = a;
    while(count){
        if(b & count){
            result ^= c;
        }
        count <<= 1;
        c = xtime(c);
    }
    return result;
}

void AESCryptosystem::subBytes() {
    for(int i = 0; i < 4; i++){
        for(int j = 0; j < 4; j++){
            _state[i][j] = AES_SBOX[_state[i][j] & 0xF0 >> 4][_state[i][j] & 0x0F];
        }
    }
}

void AESCryptosystem::shiftRows() {
    Byte tmp[4][4];
    for(int i = 0; i < 4; i++){
        for(int j = 0; j < 4; j++){
            tmp[i][j] = _state[i][j];
        }
    }
    for(int i = 1; i < 4; i++){
        for(int j = 0; j < 4; j++){
            _state[i][j] = tmp[i][(j + i) % 4];
        }
    }
}

void AESCryptosystem::mixColumns() {
    for(int i = 0; i < 4; i++){
        _state[0][i] = ffadd(ffadd(ffmultiply(0x02, _state[0][i]), ffmultiply(0x03, _state[1][i])),
                             ffadd(_state[2][i], _state[3][i]));
        _state[1][i] = ffadd(ffadd(_state[0][i], ffmultiply(0x02, _state[1][i])),
                             ffadd(ffmultiply(0x03, _state[2][i]), _state[3][i]));
        _state[2][i] = ffadd(ffadd(_state[0][i], _state[1][i]),
                             ffadd(ffmultiply(0x02, _state[2][i]), ffmultiply(0x03, _state[3][i])));
        _state[3][i] = ffadd(ffadd(ffmultiply(0x03, _state[0][i]), _state[1][i]),
                             ffadd(_state[2][i], ffmultiply(0x02, _state[3][i])));
    }
}

void AESCryptosystem::addRoundKey() {
    const Byte *bp = _initialKey.next();
    for(int i = 0; i < 4; i++){
        for(int j = 0; j < 4; j++){
            _state[j][i] ^= bp[(i*4)+j];
        }
    }
}

void AESCryptosystem::invSubBytes() {
    for(int i = 0; i < 4; i++){
        for(int j = 0; j < 4; j++){
            _state[i][j] = AES_INVERSE_SBOX[_state[i][j] & 0xF0 >> 4][_state[i][j] & 0x0F];
        }
    }
}

void AESCryptosystem::invShiftRows() {
    Byte tmp[4][4];
    for(int i = 0; i < 4; i++){
        for(int j = 0; j < 4; j++){
            tmp[i][j] = _state[i][j];
        }
    }
    for(int i = 1; i < 4; i++){
        for(int j = 0; j < 4; j++){
            _state[i][j] = tmp[i][(4 - i + j) % 4];
        }
    }
}

void AESCryptosystem::invMixColumns() {
    for(int i = 0; i < 4; i++){
        _state[0][i] = ffadd(ffadd(ffmultiply(0x0E, _state[0][i]), ffmultiply(0x0B, _state[1][i])),
                             ffadd(ffmultiply(0x0D, _state[2][i]), ffmultiply(0x09, _state[3][i])));
        _state[1][i] = ffadd(ffadd(ffmultiply(0x09, _state[0][i]), ffmultiply(0x0E, _state[1][i])),
                             ffadd(ffmultiply(0x0B, _state[2][i]), ffmultiply(0x0D, _state[3][i])));
        _state[2][i] = ffadd(ffadd(ffmultiply(0x0D, _state[0][i]), ffmultiply(0x09, _state[1][i])),
                             ffadd(ffmultiply(0x0E, _state[2][i]), ffmultiply(0x0B, _state[3][i])));
        _state[3][i] = ffadd(ffadd(ffmultiply(0x0B, _state[0][i]), ffmultiply(0x0D, _state[1][i])),
                             ffadd(ffmultiply(0x09, _state[2][i]), ffmultiply(0x0E, _state[3][i])));
    }
}

void AESCryptosystem::printState(std::string prefix) {
    std::cout << prefix << "   ";
    for(int i = 0; i < 4; i++){
        for(int j = 0; j < 4; j++){
            std::cout << std::setfill('0') << std::setw(2) << std::hex << (unsigned int)_state[j][i];
        }
    }
    std::cout << std::endl;
}
