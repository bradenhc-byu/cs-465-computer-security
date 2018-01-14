/**
 * Homework 2 - Finite Field Arithmetic (CS 465 - Computer Security)
 * @author Braden Hitchcock
 *
 * This source file contains commented pseudocode of the AES Mix Columns implementation as well as working C++ code
 * for a finite field multiplication function.
 *
 * Pseudocode for AES Mix Columns Function -----------------------------------------------------------------------------
 *
 * INPUT:   The original state of the message as a 4 x 4 array of bytes
 * OUTPUT:  The transformed state of the message as a 4 x 4 array of bytes
 *
 *  MixColumns(state){
 *      a =: an array of the coefficients of the fixed polynomial  3x^3 + x^2 + x + 2, thus [3,1,1,2])
 *      result_state =: a copy of the input byte matrix
 *      c =: the column counter, initialized to 0
 *      for c < 4{
 *          result_state[0][c] = ffmult(a[3], state[0][c]) xor ffmult(a[0], state[1][c]) xor state[2][c] xor state[3][c]
 *          result_state[1][c] = state[0][c] xor ffmult(a[3], state[1][c]) xor ffmult(a[0], state[2][c]) xor state[3][c]
 *          result_state[2][c] = state[0][c] xor state[1][c] xor ffmult(a[3], state[2][c]) xor ffmult(a[0], state[3][c])
 *          result_state[3][c] = ffmult(a[0], state[0][c]) xor state[1][c] xor state[2][c] xor ffmult(a[x], state[3]c[])
 *          c = c + 1
 *      }
 *      return result_state
 *  }
 *
 * Pseudocode for Finite Field Multiplication function used in AES Mixed Columns Function
 * (NOTE: this places the below implemented xtime() function within the ffmultiply function
 *
 * INPUT: two bytes a and b
 * OUTPUT: one byte representing the multiplication of a and b modulo an irreducible polynomial x^8 + x^4 + x^3 + x + 1
 *
 *  ffmultiply(a, b){
 *      result =: 0
 *      count =: 0
 *      for count < 8 {
 *          if the low bit in b is set {
 *              add 'a' to the result (xor)
 *          }
 *          Check if the high bit is set in a
 *          Shift a to the left one bit
 *          If the high bit was set {
 *              xor a with 0x1B (the lower 8 bits of the irreducible polynomial) to prevent overflow
 *          }
 *          Shift b to the right 1
 *          count = count + 1
 *      }
 *      return result
 *  }
 */

// Include necessary headers
#include <iostream>

// Create byte typedef for aesthetics
typedef unsigned char Byte;

/** Finite Field Multiplication function */
Byte xtime(Byte a){
    return (a & 0x80) ? (Byte)((a << 1) ^ 0x1B) : (Byte)(a << 1);
}

Byte ffmultiply(Byte a, Byte b){
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

// Main execution
int main() {
    std::cout << (int) ffmultiply(0x57, 0x83) << std::endl; // RESULT: 0xC1 (or 193)
    return 0;
}