"""
This file contains a class that uses the SHA-1 algorithm for generating hashes, but offers a wrapper that takes
string inputs and generates hashes of a specific size
"""
import hashlib


class SHA1Wrapper(object):
    """
    This class creates a wrapper around the SHA-1 hashining algorithm in Python's hashlib library. It allows us
    to hash text to a specific number of bits
    """
    @staticmethod
    def hash(text, size, hexbase=False):
        """
        Hashes the provided text and truncates the result to an integer of the provided bit size

        :param text: The string to hash
        :param size: The size of the desired hash in bits
        :param hexbase: If set to true, will return the hex result instead of an integer

        :return The result of the truncated hash as an integer
        """
        message = hashlib.sha1()
        message.update(text.encode('utf-8'))
        shift = message.digest_size * 8 - size
        digest = int(message.hexdigest(), base=16)
        return hex(digest >> shift) if hexbase else digest >> shift


def main():
    shaw = SHA1Wrapper()
    r = shaw.hash(text="Hello World!!", size=8)
    print(r)
    r = shaw.hash(text="Hello World!", size=8)
    print(r)


if __name__ == "__main__":
    main()
