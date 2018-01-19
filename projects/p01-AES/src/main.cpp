#include <iostream>
#include "AESCrypto.h"

void printHexBytes(std::vector<Byte>, std::string);

int main() {

    std::cout << "Beginning AESCryptosystem test..." << std::endl;

    Byte firstKey[] = {
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09,
            0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f
    };

    Byte plaintext1[] = {
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff
    };

    AESKey key1(firstKey, AESKeyMode::BIT_128);
    EncryptedMessage message;
    message.setMessage(plaintext1, 16);

    // Begin encryption
    AESCrypto cryptoSystem;
    cryptoSystem.setKey(key1);
    printHexBytes(message.getByteVector(), "Original message:");
    EncryptedMessage cipher = cryptoSystem.encrypt(message);
    printHexBytes(cipher.getByteVector(), "After encryption:");
    EncryptedMessage original = cryptoSystem.decrypt(cipher);
    printHexBytes(original.getByteVector(), "After decryption:");

    std::cout << "AESCryptosystem test completed" << std::endl;

    return 0;
}

void printHexBytes(std::vector<Byte> bytes, std::string prefix){
    std::cout << prefix << " " << std::hex;
    for(int i = 0; i < bytes.size(); i++){
        std::cout << (int)bytes[i];
    }
    std::cout << std::endl;
}