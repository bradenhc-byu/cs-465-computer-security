//
// Created by braden on 2/1/18.
//

#include "HashAttackSimulator.h"

HashAttackSimulator::HashAttackSimulator() {
    _strings = nullptr;
}

HashAttackSimulator::~HashAttackSimulator() = default;

int HashAttackSimulator::collisionAttack(size_t bitSize, int rounds) {
    int attempts[rounds];
    for(int i = 0; i < rounds; i++){
        std::map<unsigned int, std::string> hashes;
        std::string w = randomString();
        unsigned int h = _shaw.hash(w,bitSize);
        std::map<unsigned int, std::string>::iterator it;
        while((it = hashes.find(h)) == hashes.end()
                || it->second == w){
            hashes[h] = w;
            w = randomString();
            h = _shaw.hash(w, bitSize);
        }
        attempts[i] = hashes.size();
    }
    int sum = 0;
    for(int i : attempts){sum += i;}
    return sum / rounds;
}

int HashAttackSimulator::preImageAttack(size_t bitSize, int rounds) {
    int attempts[rounds];
    for(int i = 0; i < rounds; i++){
        std::vector<std::string> words;
        std::string w = randomString();
        unsigned int h = _shaw.hash(w, bitSize);
        std::string c = randomString();
        unsigned int ch = _shaw.hash(c, bitSize);
        words.push_back(c);
        while(ch != h){
            while(std::find(words.begin(), words.end(), c) != words.end()){
                c = randomString();
            }
            words.push_back(c);
            ch = _shaw.hash(c, bitSize);
        }
        attempts[i] = words.size();
    }
    int sum = 0;
    for(int i : attempts){sum += i;}
    return sum / rounds;
}

double HashAttackSimulator::theoreticalCollisionAttack(size_t bitSize) {
    return std::pow(2,(float)bitSize / 2.0);
}

double HashAttackSimulator::theoreticalPreImageAttack(size_t bitSize) {
    return std::pow(2,bitSize);
}

std::string HashAttackSimulator::randomString() {
    std::string str(10,0);
    std::generate_n( str.begin(), 10, randchar );
    return str;
}

char HashAttackSimulator::randchar() {
    std::random_device rd;
    std::mt19937 mt(rd());
    std::uniform_int_distribution<int> dist(1, 62);
    const char charset[] = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
    return charset[ dist(mt) ];
}

void HashAttackSimulator::generateStrings(size_t size) {
    if(_strings != nullptr) delete _strings;
    _strings = new std::string[size];
    for(int i = 0; i < size; i++){
        std::string w = randomString();
        _strings[i] = randomString();
    }
}
