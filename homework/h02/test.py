def main():
    message = [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
               0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]

    key = 0x11001011

    cipher = []

    for i in xrange(0, 16, 2):
        word = (message[i] << 8) ^ message[i+1]
        eword = word ^ key
        cipher.append(eword >> 8)
        cipher.append(eword & 0xFF)

    print cipher




if __name__ == "__main__":
    main()