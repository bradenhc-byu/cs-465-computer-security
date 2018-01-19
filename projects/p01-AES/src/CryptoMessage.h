//
// Created by braden on 1/17/18.
//

#ifndef AESCRYPTOSYSTEM_CRYPTOMESSAGE_H
#define AESCRYPTOSYSTEM_CRYPTOMESSAGE_H

#include <string>
#include <vector>

#include "AESDefinitions.h"

class CryptoMessage {

public:
    CryptoMessage();
    virtual ~CryptoMessage();

    explicit CryptoMessage(std::string& msg);
    explicit CryptoMessage(const char* msg);
    explicit CryptoMessage(Byte* msg);

    void setMessage(std::string& msg);
    void setMessage(Byte* msg);
    void setChunkSize(size_t size);
    void append(Byte* chunk);
    void append(std::vector<Byte> chunk);

    size_t size();
    std::vector<Byte>& getMessage();
    std::vector<Byte> nextChunk();

    std::string toString();

    static const size_t CHUNK_128 = 16;


private:

    std::vector<Byte> _message;
    size_t _byteIndex;
    size_t _size;
    size_t _chunkSize;

};


#endif //AESCRYPTOSYSTEM_CRYPTOMESSAGE_H
