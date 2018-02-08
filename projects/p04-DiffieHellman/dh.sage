"""
Lab 4: Diffie-Hellman
Braden Hitchcock
CS 465 - Computer Security
"""
import os
from sage.all import *


def exponentiate(g, a, m):
    """
    Uses modular exponentiation to calculate a large number raised to a power mod another number.
    :param g: The base
    :param a: The exponenet
    :param m: The modulus
    """
    shifter = int(bin(a),2)
    result = 1
    power = 1
    while shifter != 0:
        # If the low bit is set after the shift, multiply
        if shifter & 0x01:
            result = result * ((g ** power) % m) % m
        # Adjust the exponent
        power = 2 if power == 1 else power * 2
        # Move on to the next value
        shifter = shifter >> 1
    return result

def diffie_hellman(g=5, key_size=64):
    """
    Generates a secure prime p and secret exponenet s to use in a Diffie-Hellman key
    exchange.
    :param g: The base to use when calculating g^s % p. Default is 5
    :param key_size: The size in bytes of p and s. Default is 64.
    :return: three values: g^s % p, p, and s
    """
    print("Generating a secure prime p...")
    p = int(os.urandom(key_size).encode('hex'), 16)
    p = next_prime(p)
    while not is_prime((p - 1) / 2):
        p = int(os.urandom(key_size).encode('hex'), 16)
        p = next_prime(p)
    print("Generating a secure private exponent s...")
    s = int(os.urandom(key_size).encode('hex'), 16)
    s = next_prime(s)
    print("Calculating exponent...")
    gsp = exponentiate(g,s,p)
    print("Complete!")
    return gsp, p, s


def calculate_key(r, s, p):
    return exponentiate(r,s,p)


def main():
    r = exponentiate(2,42,78)
    print(r)


if __name__ == "__main__":
    #main()
    print("Loaded")
