//
// Created by braden on 1/17/18.
//

#include "CryptoMessage.h"

CryptoMessage::CryptoMessage() {
    _size = 0;
    _byteIndex = 0;
    _chunkSize = 0;
}

CryptoMessage::~CryptoMessage() {

}

CryptoMessage::CryptoMessage(std::string& msg) {
    setMessage(msg);
    _chunkSize = CHUNK_128;
}

CryptoMessage::CryptoMessage(const char *msg) {
    std::string m(msg);
    setMessage(m);
    _chunkSize = CHUNK_128;
}

CryptoMessage::CryptoMessage(Byte *msg) {
    setMessage(msg);
    _chunkSize = CHUNK_128;
}

void CryptoMessage::setMessage(std::string& msg) {
    _size = msg.length();
    for(int i = 0; i < _size; i ++){
        _message.push_back((Byte)msg[i]);
    }
    _byteIndex = 0;
}

void CryptoMessage::setMessage(Byte *msg) {
    _size = *(&msg + 1) - msg;
    for(int i = 0; i < _size; i ++){
        _message.push_back((Byte)msg[i]);
    }
    _byteIndex = 0;
}

void CryptoMessage::append(Byte *chunk) {
    size_t size = *(&chunk + 1) - chunk;
    for(int i = 0; i < size; i++){
        _message.push_back(chunk[i]);
    }
}

void CryptoMessage::append(std::vector<Byte> chunk) {
    _message.insert(_message.end(), chunk.begin(), chunk.end());
}

size_t CryptoMessage::size() {
    return _message.size();
}

void CryptoMessage::setChunkSize(size_t size) {
    _chunkSize = size;
}

std::vector<Byte> &CryptoMessage::getMessage() {
    return _message;
}

std::vector<Byte> CryptoMessage::nextChunk() {
    if(_byteIndex >= _size){
        return std::vector<Byte>();
    }
    if(_byteIndex + _chunkSize > _message.size()){
        std::vector<Byte> chunk(_chunkSize, Byte());
        for(int i = 0; i < _message.size() - _byteIndex; i++){
            chunk[i] = _message.at(_byteIndex);
            _byteIndex++;
        }
        return chunk;
    }
    std::vector<Byte> chunk(_chunkSize, Byte());
    for(int i = 0; i < _chunkSize; i++){
        chunk[i] = _message.at(_byteIndex);
        _byteIndex++;
    }
    return chunk;
}

std::string CryptoMessage::toString() {
    std::string msg;
    for(int i = 0; i < _size; i++){
        msg.append((char*)_message[i]);
    }
    return msg;
}
