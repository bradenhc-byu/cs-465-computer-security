#include <iostream>
#include "AESCryptosystem.h"

int main() {

    std::cout << "Beginning AESCryptosystem test..." << std::endl;

    AESKey key(AESMode::BIT_128)
    AESCryptosystem cryptosystem(key);
    unsigned char message[8] = "hello";
    unsigned char* ciphertext = NULL;
    cryptosystem.encrypt(message, ciphertext);

    std::cout << "AESCryptosystem test completed" << std::endl;

    return 0;
}