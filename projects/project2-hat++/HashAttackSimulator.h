//
// Created by braden on 2/1/18.
//

#ifndef HASHATTACKS_HASHATTACKSIMULATOR_H
#define HASHATTACKS_HASHATTACKSIMULATOR_H

#include <cstdlib>
#include <map>
#include <vector>
#include <string>
#include <random>
#include <math.h>
#include <functional> //for std::function
#include <algorithm>  //for std::generate_n

#include "SHA1Wrapper.h"

class HashAttackSimulator {

public:
    HashAttackSimulator();

    virtual ~HashAttackSimulator();

    int collisionAttack(size_t bitSize, int rounds);

    int preImageAttack(size_t bitSize, int rounds);

    double theoreticalCollisionAttack(size_t bitSize);
    double theoreticalPreImageAttack(size_t bitSize);

    static char randchar();

private:
    std::string randomString();
    void generateStrings(size_t size);

    SHA1Wrapper _shaw;
    std::string *_strings;

};


#endif //HASHATTACKS_HASHATTACKSIMULATOR_H
