//
// Created by braden on 1/18/18.
//

#include "EncryptedMessage.h"

EncryptedMessage::EncryptedMessage() = default;

EncryptedMessage::~EncryptedMessage() = default;

void EncryptedMessage::setMessage(std::string msg) {
    for(char c : msg){
        _message.push_back((Byte)c);
    }
}

void EncryptedMessage::setMessage(const char *msg) {
    std::string s(msg);
    for(char c : s){
        _message.push_back((Byte)c);
    }
}

void EncryptedMessage::setMessage(Byte *byte, int size) {
    for(int i = 0; i < size; i++){
        _message.push_back(byte[i]);
    }
}

void EncryptedMessage::setMessage(std::vector<Byte> msg) {
    _message.clear();
    _message.insert(_message.end(), msg.begin(), msg.end());
}

const std::vector<Byte>& EncryptedMessage::getByteVector() {
    return _message;
}

Byte *EncryptedMessage::getByteArray() {
    auto *bytes = new Byte[_message.size()]();
    for(int i = 0; i < _message.size(); i++){
        bytes[i] = _message.at(i);
    }
    return bytes;
}

std::string EncryptedMessage::getMessageString() {
    std::string s;
    for(Byte b : _message){
        s += b;
    }
    return s;
}

size_t EncryptedMessage::length() {
    return _message.size();
}
