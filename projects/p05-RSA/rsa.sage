"""
Lab 05: RSA
Braden Hitchcock
CS 465 - Computer Security
"""
from sage.all import *
import os
import math


def exponentiate(g, a, m):
    """
    Uses modular exponentiation to calculate a large number raised to a power mod another number.
    :param g: The base
    :param a: The exponenet
    :param m: The modulus
    """
    shifter = int(bin(a),2)
    result = mod(1,n)
    power = 1
    while shifter != 0:
        # If the low bit is set after the shift, multiply
        if shifter & 0x01:
            result = result * int(math.pow(g, power) % m)
        # Adjust the exponent
        power = 2 if power == 1 else power * 2
        # Move on to the next value
        shifter = shifter >> 1
    return result


def extended_gcd(a, b):
    """
    Implementation of the Extended Euclidean Algorithm
    :param a: first number
    :param b: second number
    :return: a three-tuple containing (GCD, s, t) in the equation as + bt = GCD(a,b)
    """
    s = 0
    old_s = 1
    t = 1
    old_t = 0
    r = b
    old_r = a
    while r != 0:
        q = old_r // r
        old_r, r = (r, (old_r - q * r))
        old_s, s = (s, (old_s - q * s))
        old_t, t = (t, (old_t - q * t))
    return old_r, old_s, old_t


def invert(a, n):
    """
    Finds the multiplicitive inverse of a modulo n
    :param a: The number to invert
    :param n: The modulo
    :return: The inverse of a mod n
    """
    t = 0
    newt = 1
    r = n
    newr = a
    while newr != 0:
        q = r // newr
        t, newt = (newt, t - q * newt)
        r, newr = (newr, r - q * newr)
    if r > 1:
        print("a is not invertable")
    else:
        if t < 0:
            t = t + n
        return t


def get_p_q(byte_length):
    """
    Wrapper method for computing values of p and q that have their high order bit set
    :param byte_length: the length of p and q in bytes (for number generation)
    :return: p and q with byte_length bytes each and their high order bit set
    """
    print("Generating p...")
    p = int(os.urandom(byte_length).encode('hex'), 16)
    p = next_prime(p)
    while p >> (byte_length * 8 - 1) != 1:
        p = int(os.urandom(byte_length).encode('hex'), 16)
        p = next_prime(p)
    print("Generating q...")
    q = int(os.urandom(byte_length).encode('hex'), 16)
    q = next_prime(q)
    while q >> (byte_length * 8 - 1) != 1:
        q = int(os.urandom(byte_length).encode('hex'), 16)
        q = next_prime(q)
    return p, q


def generate_factors(e, byte_length):
    """
    Wrapper function that will generate the values for p and q that produce a Phi(n) that produces
    GCD(e, Phi(n)) = 1
    :param e: The RSA exponent
    :param byte_length: the required length of p and q in bytes
    :return: p and q such that they conform to the above specs
    """
    p, q = get_p_q(byte_length)
    phi_n = (p - 1) * (q - 1)
    # TODO: implement gcd
    while extended_gcd(e, phi_n)[0] != 1:
        p, q = get_p_q()
        phi_n = (p - 1) * (q - 1)
    return p,q


def rsa(byte_length=64, e=65537):
    """
    Generates an RSA public and private key
    """
    print("Getting factors...")
    p,q = generate_factors(e, byte_length)
    print("Calculating n and phi_n...")
    n = p * q
    phi_n = (p - 1) * (q - 1)
    print("Calculating d...")
    d = extended_gcd(e,phi_n)[1]
    d = d % phi_n
    print("Complete!")
    return n,e,d,p,q

def rsa_encrypt(message, e, n):
    return exponentiate(message,e,n)

def rsa_decrypt(cipher, d, n):
    return exponentiate(cipher, d, n)

# Helper functions and definitions for converting numbers to text and back
ntt = {0: ' ', 1: '!', 2: '"', 3: '#', 4: '$', 5: '%', 6: '&', 7: "'", 8: '(', 9: ')', 10: '*', 11: '+', 
       12: ',', 13: '-', 14: '.', 15: '/', 16: '0', 17: '1', 18: '2', 19: '3', 20: '4', 21: '5', 22: '6', 
       23: '7', 24: '8', 25: '9', 26: ':', 27: ';', 28: '<', 29: '=', 30: '>', 31: '?', 32: '@', 33: 'A', 
       34: 'B', 35: 'C', 36: 'D', 37: 'E', 38: 'F', 39: 'G', 40: 'H', 41: 'I', 42: 'J', 43: 'K', 44: 'L', 
       45: 'M', 46: 'N', 47: 'O', 48: 'P', 49: 'Q', 50: 'R', 51: 'S', 52: 'T', 53: 'U', 54: 'V', 55: 'W', 
       56: 'X', 57: 'Y', 58: 'Z', 59: '[', 60: '\\', 61: ']', 62: '^', 63: '_', 64: '`', 65: 'a', 66: 'b', 
       67: 'c', 68: 'd', 69: 'e', 70: 'f', 71: 'g', 72: 'h', 73: 'i', 74: 'j', 75: 'k', 76: 'l', 77: 'm', 
       78: 'n', 79: 'o', 80: 'p', 81: 'q', 82: 'r', 83: 's', 84: 't', 85: 'u', 86: 'v', 87: 'w', 88: 'x', 
       89: 'y', 90: 'z', 91: '{', 92: '|', 93: '}', 94: '~', 95: '¢', 96: '£', 97: '«', 98: '»', 99: '±'}

ttn = dict((v,k) for k, v in ntt.iteritems())

def text_to_num(text):
    num = 0
    for i in range(len(text)):
        num *= 100
        num += ttn[text[i]]
    return num

def num_to_text(num):
    text = ''
    num = int(num)
    while num > 0:
        cha = (num%100)
        text = ntt[cha] + text
        num = (num-cha)/100
    return text
    
    
