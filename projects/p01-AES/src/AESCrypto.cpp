//
// Created by braden on 1/18/18.
//

#include "AESCrypto.h"

AESCrypto::AESCrypto() = default;

AESCrypto::~AESCrypto() = default;

void AESCrypto::setKey(AESKey key) {
    _key = key;
}

EncryptedMessage AESCrypto::encrypt(EncryptedMessage message) {
    std::vector<Byte> cipherVector;
    int chunkSize = 16;
    size_t messageIndex = 0;
    size_t remainingBytes = message.length();
    int rounds = 0;
    switch(_key.mode()){
        case BIT_128: rounds = 10; break;
        case BIT_192: rounds = 12; break;
        case BIT_256: rounds = 14; break;
    }

    while(remainingBytes){
        // Initialize the next state
        clearState();
        for(int i = 0; i < chunkSize; i++){
            if(remainingBytes == 0) break;
            _state[i % 4][i / 4] = message.getByteVector().at(messageIndex++);
            remainingBytes--;
        }

        printState("round[0].input");

        // Encrypt
        addRoundKey();

        for(int i = 1; i < rounds; i++){
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
        _key.resetSchedule();


        // Append the state to the message
        for(int i = 0; i < 4; i++){
            for(int j = 0; j < 4; j++){
                cipherVector.push_back(_state[j][i]);
            }
        }
    }

    EncryptedMessage cipher;
    cipher.setMessage(cipherVector);
    return cipher;
}

EncryptedMessage AESCrypto::decrypt(EncryptedMessage cipher) {
    std::vector<Byte> messageVector;
    int chunkSize = 16;
    size_t messageIndex = 0;
    size_t remainingBytes = cipher.length();
    int rounds = 0;
    switch(_key.mode()){
        case BIT_128: rounds = 10; break;
        case BIT_192: rounds = 12; break;
        case BIT_256: rounds = 14; break;
    }

    while(remainingBytes){
        // Initialize the next state
        clearState();
        for(int i = 0; i < chunkSize; i++){
            if(remainingBytes == 0) break;
            _state[i % 4][i / 4] = cipher.getByteVector().at(messageIndex++);
            remainingBytes--;
        }

        printState("round[0].input");

        // Decrypt
        invAddRoundKey();

        for(int i = 1; i < rounds; i++){
            std::stringstream prefix;
            prefix << "round[" << i << "].";
            printState(prefix.str() + "istart");
            invShiftRows();
            printState(prefix.str() + "is_row");
            invSubBytes();
            printState(prefix.str() + "is_box");
            invAddRoundKey();
            printState(prefix.str() + "ik_add");
            invMixColumns();
        }

        invShiftRows();
        invSubBytes();
        invAddRoundKey();

        // Reset the the head of the key schedule
        _key.resetSchedule();


        // Append the state to the message
        for(int i = 0; i < 4; i++){
            for(int j = 0; j < 4; j++){
                messageVector.push_back(_state[j][i]);
            }
        }
    }

    EncryptedMessage message;
    message.setMessage(messageVector);
    return message;
}

Byte AESCrypto::ffadd(Byte a, Byte b) {
    return a ^ b;
}

Byte AESCrypto::xtime(Byte a) {
    return (a & 0x80) ? (Byte)((a << 1) ^ 0x1B) : (Byte)(a << 1);
}

Byte AESCrypto::ffmultiply(Byte a, Byte b) {
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

void AESCrypto::subBytes() {
    for(int i = 0; i < 4; i++){
        for(int j = 0; j < 4; j++){
            _state[i][j] = AES_SBOX[(_state[i][j] & 0xF0) >> 4][_state[i][j] & 0x0F];
        }
    }
}

void AESCrypto::shiftRows() {
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

void AESCrypto::mixColumns() {
    Byte tmp[4][4];
    for(int i = 0; i < 4; i++){
        for(int j = 0; j < 4; j++){
            tmp[i][j] = _state[i][j];
        }
    }
    for(int i = 0; i < 4; i++){
        _state[0][i] = ffadd(ffadd(ffmultiply(0x02, tmp[0][i]), ffmultiply(0x03, tmp[1][i])),
                             ffadd(tmp[2][i], tmp[3][i]));
        _state[1][i] = ffadd(ffadd(tmp[0][i], ffmultiply(0x02, tmp[1][i])),
                             ffadd(ffmultiply(0x03, tmp[2][i]), tmp[3][i]));
        _state[2][i] = ffadd(ffadd(tmp[0][i], tmp[1][i]),
                             ffadd(ffmultiply(0x02, tmp[2][i]), ffmultiply(0x03, tmp[3][i])));
        _state[3][i] = ffadd(ffadd(ffmultiply(0x03, tmp[0][i]), tmp[1][i]),
                             ffadd(tmp[2][i], ffmultiply(0x02, tmp[3][i])));
    }
}

void AESCrypto::addRoundKey() {
    Byte **bp = _key.nextScheme();
    for(int i = 0; i < 4; i++){
        for(int j = 0; j < 4; j++){
            _state[i][j] ^= bp[i][j];
        }
    }
}

void AESCrypto::invAddRoundKey() {
    Byte **bp = _key.inextScheme();
    for(int i = 0; i < 4; i++){
        for(int j = 0; j < 4; j++){
            _state[i][j] ^= bp[i][j];
        }
    }
}

void AESCrypto::invSubBytes() {
    for(int i = 0; i < 4; i++){
        for(int j = 0; j < 4; j++){
            _state[i][j] = AES_INVERSE_SBOX[(_state[i][j] & 0xF0) >> 4][_state[i][j] & 0x0F];
        }
    }
}

void AESCrypto::invShiftRows() {
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

void AESCrypto::invMixColumns() {
    Byte tmp[4][4];
    for(int i = 0; i < 4; i++){
        for(int j = 0; j < 4; j++){
            tmp[i][j] = _state[i][j];
        }
    }
    for(int i = 0; i < 4; i++){
        _state[0][i] = ffadd(ffadd(ffmultiply(0x0E, tmp[0][i]), ffmultiply(0x0B, tmp[1][i])),
                             ffadd(ffmultiply(0x0D, tmp[2][i]), ffmultiply(0x09, tmp[3][i])));
        _state[1][i] = ffadd(ffadd(ffmultiply(0x09, tmp[0][i]), ffmultiply(0x0E, tmp[1][i])),
                             ffadd(ffmultiply(0x0B, tmp[2][i]), ffmultiply(0x0D, tmp[3][i])));
        _state[2][i] = ffadd(ffadd(ffmultiply(0x0D, tmp[0][i]), ffmultiply(0x09, tmp[1][i])),
                             ffadd(ffmultiply(0x0E, tmp[2][i]), ffmultiply(0x0B, tmp[3][i])));
        _state[3][i] = ffadd(ffadd(ffmultiply(0x0B, tmp[0][i]), ffmultiply(0x0D, tmp[1][i])),
                             ffadd(ffmultiply(0x09, tmp[2][i]), ffmultiply(0x0E, tmp[3][i])));
    }
}

void AESCrypto::printState(std::string prefix) {
    std::cout << prefix << "   ";
    for(int i = 0; i < 4; i++){
        for(int j = 0; j < 4; j++){
            std::cout << std::setfill('0') << std::setw(2) << std::hex << (unsigned int)_state[j][i];
        }
    }
    std::cout << std::endl;
}

void AESCrypto::clearState() {
    for(int i = 0; i < 4; i++){
        for(int j = 0; j < 4; j++){
            _state[i][j] = 0x00;
        }
    }
}
