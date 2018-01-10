//
// Created by braden on 1/9/18.
//

#include "AESCryptosystem.h"

AESCryptosystem::~AESCryptosystem() {

}

AESCryptosystem::AESCryptosystem(AESKey key) {
    this->_initialKey = key;
}

void AESCryptosystem::setKey(AESKey key) {
    this->_initialKey = key;
}

void AESCryptosystem::encrypt(unsigned char* plaintext, unsigned char* ciphertext) {

}

void AESCryptosystem::decrypt(unsigned char *ciphertext, unsigned char *plaintext) {

}

void AESCryptosystem::encrypt128(unsigned char *plaintext, unsigned char *ciphertext) {

}

void AESCryptosystem::encrypt192(unsigned char *plaintext, unsigned char *ciphertext) {

}

void AESCryptosystem::encrypt256(unsigned char *plaintext, unsigned char *ciphertext) {

}

void AESCryptosystem::decrypt128(unsigned char *ciphertext, unsigned char *plaintext) {

}

void AESCryptosystem::decrypt192(unsigned char *ciphertext, unsigned char *plaintext) {

}

void AESCryptosystem::decrypt256(unsigned char *ciphertext, unsigned char *plaintext) {

}
