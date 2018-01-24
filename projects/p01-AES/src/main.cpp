#include <iostream>
#include "AESCrypto.h"

void printHexBytes(std::vector<Byte>, std::string);

int main() {

    Byte firstKey[] = {
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09,
            0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f
    };

    Byte secondKey[] = {
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09,
            0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13,
            0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e,
            0x1f
    };

    Byte thirdKey[] = {
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09,
            0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13,
            0x15, 0x16, 0x17
    };

    Byte plaintext[] = {
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff
    };

    AESKey key1(firstKey, AESKeyMode::BIT_128);
    AESKey key2(secondKey, AESKeyMode::BIT_192);
    AESKey key3(thirdKey, AESKeyMode::BIT_256);
    EncryptedMessage message;
    message.setMessage(plaintext, 16);

    std::cout << "Beginning AESCryptosystem test..." << std::endl;

    // Begin encryption
    AESCrypto cryptoSystem;
    EncryptedMessage cipher;
    EncryptedMessage original;

    // Test first key
    std::cout << "Testing 128 bit key..." << std::endl;
    cryptoSystem.setKey(key1);
    printHexBytes(message.getByteVector(), "Original message:");
    cipher = cryptoSystem.encrypt(message);
    printHexBytes(cipher.getByteVector(), "After encryption:");
    original = cryptoSystem.decrypt(cipher);
    printHexBytes(original.getByteVector(), "After decryption:");

    // Test second key
    std::cout << "Testing 192 bit key..." << std::endl;
    cryptoSystem.setKey(key2);
    printHexBytes(message.getByteVector(), "Original message:");
    cipher = cryptoSystem.encrypt(message);
    printHexBytes(cipher.getByteVector(), "After encryption:");
    original = cryptoSystem.decrypt(cipher);
    printHexBytes(original.getByteVector(), "After decryption:");

    // Test third key
    std::cout << "Testing 256 bit key..." << std::endl;
    cryptoSystem.setKey(key3);
    printHexBytes(message.getByteVector(), "Original message:");
    cipher = cryptoSystem.encrypt(message);
    printHexBytes(cipher.getByteVector(), "After encryption:");
    original = cryptoSystem.decrypt(cipher);
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