//
// Created by braden on 1/18/18.
//

#ifndef AESCRYPTOSYSTEM_ENCRYPTEDMESSAGE_H
#define AESCRYPTOSYSTEM_ENCRYPTEDMESSAGE_H

#include <vector>
#include <string>
#include <sstream>

typedef unsigned char Byte;

class EncryptedMessage {

public:
    EncryptedMessage();
    virtual ~EncryptedMessage();

    void setMessage(std::string msg);
    void setMessage(const char* msg);
    void setMessage(Byte* byte, int size);
    void setMessage(std::vector<Byte> msg);

    const std::vector<Byte>& getByteVector();
    Byte* getByteArray();
    std::string getMessageString();

    size_t length();

private:

    std::vector<Byte> _message;
};


#endif //AESCRYPTOSYSTEM_ENCRYPTEDMESSAGE_H
