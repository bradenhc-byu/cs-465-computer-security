"""
Project 3 - MAC Attack
Braden Hitchcock
CS 465 - Computer Security

This script file contains source code for project 3 in the computer security course at Brigham Young University
"""
# SUBMISSION
# Original Message: "No one has completed lab 2 so give them all a 0"
# Original MAC: f4b645e89faaec2ff8e443c595009c16dbdfba4b
#
# Message To Append: "P.S. Actually, give Braden Hitchcock 200%. He is my favorite"
#
# Hex message after append: 4e6f206f6e652068617320636f6d706c65746564206c6162203220736f2067697665207468656d20616c6c
#                           20612030800000000000000000000000000000000000000000000000000000000000000000000000000000
#                           00000000000000000000000000000000000000000000000001f8502e532e2041637475616c6c792c206769
#                           76652042726164656e204869746368636f636b20323030252e204865206973206d79206661766f72697465
#
# New MAC Hash: 7061daee3b7dc4993f751bfe910e69367c915604
#
import hashlib
import binascii

def sha1(data, seed=None, length=None):
    """
    This modified implementation of SHA-1 was taken from Stack Exchange and was originally written
    by Kyle Kersey (kyle k), ranked top 15% on Stack Exchange.
    If time permits, I will follow the FIPS specs and implement my own version. Since our own implementation is
    not a requirement for this lab, I have decided to use someone else's.
    I have made changes to allow for a intermediate hash to be used as the seed hash.

    Modifications made by Braden Hitchcock

    :param data: The message data to hash
    :param seed: A list of 5 integer objects representing a SHA-1 hash to start the hashing process at
    :return: A string representation of a SHA-1 hexadecimal message digest hash
    """
    sha1_bytes = ""

    if seed is None:
        # These were taken from the FIPS specification
        seed = [0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0]
    elif type(seed) is not list or len(seed) != 5:
        # If the use supplied an intermediate hash seed, then make sure it is correctly formatted
        raise Exception("sha1() seed requires a list of 5 integers")

    if length is None:
        # We need to adjust the start length of the hash depending on if we are just hashing from the start
        # or if we are attacking the hash with a seed. If no adjusted length is given, set it to the default
        length = len(data) * 8

    # Initialize the registers
    h0 = seed[0]
    h1 = seed[1]
    h2 = seed[2]
    h3 = seed[3]
    h4 = seed[4]

    # Pad the message
    for n in range(len(data)):
        sha1_bytes+='{0:08b}'.format(ord(data[n]))
    bits = sha1_bytes+"1"
    pBits = bits
    # Pad until length equals 448 mod 512
    while len(pBits)%512 != 448:
        pBits+="0"
    # Append the original length in bytes (64-bit long)
    pBits+='{0:064b}'.format(length)

    # Define some components to the algorithm
    def chunks(l, n):
        return [l[i:i+n] for i in range(0, len(l), n)]

    def rol(n, b):
        return ((n << b) | (n >> (32 - b))) & 0xffffffff

    # Initialize internal registers and variables for the hash
    for c in chunks(pBits, 512):
        words = chunks(c, 32)
        w = [0]*80
        for n in range(0, 16):
            w[n] = int(words[n], 2)
        for i in range(16, 80):
            w[i] = rol((w[i-3] ^ w[i-8] ^ w[i-14] ^ w[i-16]), 1)

        a = h0
        b = h1
        c = h2
        d = h3
        e = h4

        # Main loop of execution (SHA-1 Hash)
        for i in range(0, 80):
            if 0 <= i <= 19:
                f = (b & c) | ((~b) & d)
                k = 0x5A827999
            elif 20 <= i <= 39:
                f = b ^ c ^ d
                k = 0x6ED9EBA1
            elif 40 <= i <= 59:
                f = (b & c) | (b & d) | (c & d)
                k = 0x8F1BBCDC
            elif 60 <= i <= 79:
                f = b ^ c ^ d
                k = 0xCA62C1D6

            temp = rol(a, 5) + f + e + k + w[i] & 0xffffffff
            e = d
            d = c
            c = rol(b, 30)
            b = a
            a = temp

        h0 = h0 + a & 0xffffffff
        h1 = h1 + b & 0xffffffff
        h2 = h2 + c & 0xffffffff
        h3 = h3 + d & 0xffffffff
        h4 = h4 + e & 0xffffffff

    return '%08x%08x%08x%08x%08x' % (h0, h1, h2, h3, h4)

def pad(message):
    """
    Implementation of the SHA-1 padding algorithm for any message of an arbitrary length
    :param message: the message bytes
    :return: the message in bytes padded according to the SHA-1 specs
    """
    length = len(message) * 8
    pad_len = (448 - length - 1) % 512
    pad_bytes = pad_len // 8
    message.append(0x80)
    for i in range(pad_bytes):
        message.append(0x00)
    for b in length.to_bytes(8, byteorder='big', signed=False):
        message.append(b)
    return message

def intermediate(digest):
    """
    Splits a SHA-1 hex digest into 5 sub-parts to seed a SHA-1 hasher in a MAC attack
    :param digest: a SHA-1 digest as a hexadecimal integer
    :return: a list of the 5 32-bit parts of the hash
    """
    h1 = digest >> 128
    h2 = (digest >> 96) & 0xFFFFFFFF
    h3 = (digest >> 64) & 0xFFFFFFFF
    h4 = (digest >> 32) & 0xFFFFFFFF
    h5 = digest & 0xFFFFFFFF
    return [h1, h2, h3, h4, h5]

def mac_attack(original, mac, extension, key_len=128):
    """
    Conducts a MAC attack on an original message given the message and the hash of that message with a prepended key.
    The key is unknown to this algorithm.
    :param original: The original message sent
    :param mac: The originally calculated mac (in this case, SHA-1 hash of key || message))
    :param extension: The desired message to append
    :param key_len: The size of the key in bits. Default is 128 bits.
    :return: A new message and new mac to send in place of the original
    """
    # Setup padding of the key
    my_message = bytearray()
    for i in range(key_len//8):
        my_message.append(0x40)
    # Append the original message
    for b in bytearray(original.encode()):
        my_message.append(b)
    # Pad the message
    my_message = pad(my_message)
    # Add my message to the end of the padded message
    for b in extension.encode():
        my_message.append(b)
    # Now remove the key, since we don't care about it anyways
    my_message = my_message[key_len//8:]
    original_digest = int(mac, 16)
    intermediate_hash = intermediate(original_digest)
    my_digest = sha1(extension, seed=intermediate_hash, length=key_len + len(my_message)*8)

    return my_message, my_digest



def main():

    test = False

    original_mac = "f4b645e89faaec2ff8e443c595009c16dbdfba4b"
    message = "No one has completed lab 2 so give them all a 0"
    append_message = "P.S. Actually, give Braden Hitchcock 200%. He is my favorite"

    # Testing and debugging
    if test:
        print("verifying correctness")
        test_key = "helloworld!!!!!!"
        test_mac = sha1(test_key + message)
        print(test_mac)
        h = hashlib.sha1()
        h.update((test_key + message).encode())
        print(h.hexdigest())
        print("Beginning attack")
        new_message, new_mac = mac_attack(message, test_mac, append_message)
        h = hashlib.sha1()
        b = bytearray()
        b.extend(test_key.encode())
        b.extend(new_message)
        h.update(b)

        print(new_message)
        print(new_mac)
        print(h.hexdigest())
    else:
        new_message, new_mac = mac_attack(message, original_mac, append_message)
        print(new_message)
        print(new_mac)
        print("SUBMISSION")
        print(binascii.hexlify(new_message))
        print(new_mac)


if __name__ == "__main__":
    main()