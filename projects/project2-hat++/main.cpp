#include <iostream>
#include "HashAttackSimulator.h"

void test(size_t bitSize, int rounds);

int main() {

    int rounds = 50;
    int bitSizes[5] = {8,14,16,18,20};
    for(int i : bitSizes){
        test(i, rounds);
    }

    return 0;
}

void test(size_t bitSize, int rounds){
    std::cout << "Testing hash attacks at " << bitSize << " bits" << std::endl;
    HashAttackSimulator simulator;
    std::cout << "Theoretical Collision Attempts : " << simulator.theoreticalCollisionAttack(bitSize) << std::endl;
    std::cout << "Experimental Collision Attempts: " << simulator.collisionAttack(bitSize, rounds) << std::endl;
    std::cout << "Theoretical Pre-Image Attempts : " << simulator.theoreticalPreImageAttack(bitSize) << std::endl;
    std::cout << "Experimental Pre-Image Attempts: " << simulator.preImageAttack(bitSize, rounds) << std::endl;
    std::cout << "Tests completed!" << std::endl;
}