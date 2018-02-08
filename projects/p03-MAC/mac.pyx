# Project 3 - MAC Attack
# Braden Hitchcock
# CS 465 - Computer Security
#
# This script file contains source code for project 3 in the computer security course at Brigham Young University
#
import hashlib

cdef unsigned char *original_data = [
	0x4e, 0x6f, 0x20, 0x6f, 0x6e, 0x65, 0x20, 0x68, 0x61, 0x73, 0x20, 0x63, 0x6f, 0x6d, 0x70, 0x6c,
	0x65, 0x74, 0x65, 0x64, 0x20, 0x6c, 0x61, 0x62, 0x20, 0x32, 0x20, 0x73, 0x6f, 0x20, 0x67, 0x69,
	0x76, 0x65, 0x20, 0x74, 0x68, 0x65, 0x6d, 0x20, 0x61, 0x6c, 0x6c, 0x20, 0x61, 0x20, 0x30
]

cdef unsigned char original_mac = "f4b645e89faaec2ff8e443c595009c16dbdfba4b"

def mac_attack(unsigned char data, unsigned char mac):

    return None


def main():
    h = hashlib.sha1()
    message = "No one has completed lab 2 so give them all a 0"
    h.update(message)
    print(h.hexdigest())
    append_message = ", except for Braden Hitchcock. Give him 125% because he is my favorite"


if __name__ == "__main__":
    main()