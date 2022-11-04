import binascii


class AES(object):
    """ Started on 3/16/2017
    The Advanced Encryption Standard (AES), also known by its original
    name Rijndael, is a specification for the encryption of electronic
    data established by the U.S. National Institute of Standards and
    Technology (NIST) in 2001. AES is a subset of the Rijndael cipher
    developed by two Belgian cryptographers, Joan Daemen and Vincent
    Rijmen, who submitted a proposal to NIST during the AES selection
    process. Rijndael is a family of ciphers with different key
    and block sizes.

    # A simple example of encrypting a string with ECB mode!
    key = 0x000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f

    aes = AES(key)
    cyphertext = aes.encrypt('Hello World!')
    plaintext = aes.decrypt(cyphertext)

    # A simple example of encrypting bytes with CBC mode!
    key = 0x000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f
    iv = 0x000102030405060708090a0b0c0d0e0f

    aes = AES(key, iv)
    cyphertext = aes.encrypt(b'Hello World!')
    plaintext = aes.decrypt(cyphertext)
    """
    def __init__(self, key, iv=None):
        self.iv = iv
        if iv and abs(iv) <= 0xffffffffffffffffffffffffffffffff:
            self.iv = "%032x" % iv
        elif iv and abs(iv) > 0xffffffffffffffffffffffffffffffff:
            raise ValueError("IV can not be larger than 128-bits.")

        if abs(key) <= 0xffffffffffffffffffffffffffffffff:
            self.Nb, self.Nk, self.Nr = 4, 4, 10
            self.key = "%032x" % key
        elif abs(key) <= 0xffffffffffffffffffffffffffffffffffffffffffffffff:
            self.Nb, self.Nk, self.Nr = 4, 6, 12
            self.key = "%048x" % key
        elif abs(key) <= 0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff:
            self.Nb, self.Nk, self.Nr = 4, 8, 14
            self.key = "%064x" % key
        else:
            raise ValueError("Key can not be larger than 256-bits.")

        self.sbox = [
            0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
            0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
            0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
            0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
            0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
            0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
            0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
            0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
            0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
            0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
            0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
            0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
            0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
            0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
            0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
            0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16]

        self.rsbox = [
            0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
            0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
            0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
            0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
            0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
            0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
            0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
            0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
            0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
            0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
            0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
            0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
            0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
            0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
            0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
            0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d]

        self.expbox = [
            0x01, 0x03, 0x05, 0x0f, 0x11, 0x33, 0x55, 0xff, 0x1a, 0x2e, 0x72, 0x96, 0xa1, 0xf8, 0x13, 0x35,
            0x5f, 0xe1, 0x38, 0x48, 0xd8, 0x73, 0x95, 0xa4, 0xf7, 0x02, 0x06, 0x0a, 0x1e, 0x22, 0x66, 0xaa,
            0xe5, 0x34, 0x5c, 0xe4, 0x37, 0x59, 0xeb, 0x26, 0x6a, 0xbe, 0xd9, 0x70, 0x90, 0xab, 0xe6, 0x31,
            0x53, 0xf5, 0x04, 0x0c, 0x14, 0x3c, 0x44, 0xcc, 0x4f, 0xd1, 0x68, 0xb8, 0xd3, 0x6e, 0xb2, 0xcd,
            0x4c, 0xd4, 0x67, 0xa9, 0xe0, 0x3b, 0x4d, 0xd7, 0x62, 0xa6, 0xf1, 0x08, 0x18, 0x28, 0x78, 0x88,
            0x83, 0x9e, 0xb9, 0xd0, 0x6b, 0xbd, 0xdc, 0x7f, 0x81, 0x98, 0xb3, 0xce, 0x49, 0xdb, 0x76, 0x9a,
            0xb5, 0xc4, 0x57, 0xf9, 0x10, 0x30, 0x50, 0xf0, 0x0b, 0x1d, 0x27, 0x69, 0xbb, 0xd6, 0x61, 0xa3,
            0xfe, 0x19, 0x2b, 0x7d, 0x87, 0x92, 0xad, 0xec, 0x2f, 0x71, 0x93, 0xae, 0xe9, 0x20, 0x60, 0xa0,
            0xfb, 0x16, 0x3a, 0x4e, 0xd2, 0x6d, 0xb7, 0xc2, 0x5d, 0xe7, 0x32, 0x56, 0xfa, 0x15, 0x3f, 0x41,
            0xc3, 0x5e, 0xe2, 0x3d, 0x47, 0xc9, 0x40, 0xc0, 0x5b, 0xed, 0x2c, 0x74, 0x9c, 0xbf, 0xda, 0x75,
            0x9f, 0xba, 0xd5, 0x64, 0xac, 0xef, 0x2a, 0x7e, 0x82, 0x9d, 0xbc, 0xdf, 0x7a, 0x8e, 0x89, 0x80,
            0x9b, 0xb6, 0xc1, 0x58, 0xe8, 0x23, 0x65, 0xaf, 0xea, 0x25, 0x6f, 0xb1, 0xc8, 0x43, 0xc5, 0x54,
            0xfc, 0x1f, 0x21, 0x63, 0xa5, 0xf4, 0x07, 0x09, 0x1b, 0x2d, 0x77, 0x99, 0xb0, 0xcb, 0x46, 0xca,
            0x45, 0xcf, 0x4a, 0xde, 0x79, 0x8b, 0x86, 0x91, 0xa8, 0xe3, 0x3e, 0x42, 0xc6, 0x51, 0xf3, 0x0e,
            0x12, 0x36, 0x5a, 0xee, 0x29, 0x7b, 0x8d, 0x8c, 0x8f, 0x8a, 0x85, 0x94, 0xa7, 0xf2, 0x0d, 0x17,
            0x39, 0x4b, 0xdd, 0x7c, 0x84, 0x97, 0xa2, 0xfd, 0x1c, 0x24, 0x6c, 0xb4, 0xc7, 0x52, 0xf6, 0x01]

        self.lnbox = [
            0x00, 0x00, 0x19, 0x01, 0x32, 0x02, 0x1a, 0xc6, 0x4b, 0xc7, 0x1b, 0x68, 0x33, 0xee, 0xdf, 0x03,
            0x64, 0x04, 0xe0, 0x0e, 0x34, 0x8d, 0x81, 0xef, 0x4c, 0x71, 0x08, 0xc8, 0xf8, 0x69, 0x1c, 0xc1,
            0x7d, 0xc2, 0x1d, 0xb5, 0xf9, 0xb9, 0x27, 0x6a, 0x4d, 0xe4, 0xa6, 0x72, 0x9a, 0xc9, 0x09, 0x78,
            0x65, 0x2f, 0x8a, 0x05, 0x21, 0x0f, 0xe1, 0x24, 0x12, 0xf0, 0x82, 0x45, 0x35, 0x93, 0xda, 0x8e,
            0x96, 0x8f, 0xdb, 0xbd, 0x36, 0xd0, 0xce, 0x94, 0x13, 0x5c, 0xd2, 0xf1, 0x40, 0x46, 0x83, 0x38,
            0x66, 0xdd, 0xfd, 0x30, 0xbf, 0x06, 0x8b, 0x62, 0xb3, 0x25, 0xe2, 0x98, 0x22, 0x88, 0x91, 0x10,
            0x7e, 0x6e, 0x48, 0xc3, 0xa3, 0xb6, 0x1e, 0x42, 0x3a, 0x6b, 0x28, 0x54, 0xfa, 0x85, 0x3d, 0xba,
            0x2b, 0x79, 0x0a, 0x15, 0x9b, 0x9f, 0x5e, 0xca, 0x4e, 0xd4, 0xac, 0xe5, 0xf3, 0x73, 0xa7, 0x57,
            0xaf, 0x58, 0xa8, 0x50, 0xf4, 0xea, 0xd6, 0x74, 0x4f, 0xae, 0xe9, 0xd5, 0xe7, 0xe6, 0xad, 0xe8,
            0x2c, 0xd7, 0x75, 0x7a, 0xeb, 0x16, 0x0b, 0xf5, 0x59, 0xcb, 0x5f, 0xb0, 0x9c, 0xa9, 0x51, 0xa0,
            0x7f, 0x0c, 0xf6, 0x6f, 0x17, 0xc4, 0x49, 0xec, 0xd8, 0x43, 0x1f, 0x2d, 0xa4, 0x76, 0x7b, 0xb7,
            0xcc, 0xbb, 0x3e, 0x5a, 0xfb, 0x60, 0xb1, 0x86, 0x3b, 0x52, 0xa1, 0x6c, 0xaa, 0x55, 0x29, 0x9d,
            0x97, 0xb2, 0x87, 0x90, 0x61, 0xbe, 0xdc, 0xfc, 0xbc, 0x95, 0xcf, 0xcd, 0x37, 0x3f, 0x5b, 0xd1,
            0x53, 0x39, 0x84, 0x3c, 0x41, 0xa2, 0x6d, 0x47, 0x14, 0x2a, 0x9e, 0x5d, 0x56, 0xf2, 0xd3, 0xab,
            0x44, 0x11, 0x92, 0xd9, 0x23, 0x20, 0x2e, 0x89, 0xb4, 0x7c, 0xb8, 0x26, 0x77, 0x99, 0xe3, 0xa5,
            0x67, 0x4a, 0xed, 0xde, 0xc5, 0x31, 0xfe, 0x18, 0x0d, 0x63, 0x8c, 0x80, 0xc0, 0xf7, 0x70, 0x07]

        self.rcon = [0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36]

    @staticmethod
    def pad(data, block=16):
        """
        Append padding to data.

        @param data: Data to be padded
        @param block: Block size
        @return: Data with padding
        """
        pad = block - (len(data) % block)
        return data + bytearray(pad for _ in range(pad))

    @staticmethod
    def unpad(data):
        """
        Un-Padding for data.

        @param data: Data to be un-padded
        @return: Data with removed padding
        """
        return data[:-data[-1]]

    @staticmethod
    def rot_word(word):
        """
        Takes a word [a0, a1, a2, a3] as input and perform a
        cyclic permutation that returns the word [a1, a2, a3, a0].

        @param word: Row within State Matrix
        @return: Circular byte left shift
        """
        return ((word << 4) | (word >> (16 - 4))) & 0xffff

    @staticmethod
    def xor(first, last):
        """
        Xor method for Cipher Block Chaining (CBC) mode.

        @param first: First encrypted block
        @param last: Last encrypted block
        @return: Xor output of two blocks
        """
        return [first[x] ^ last[x] for x in range(16)]

    @staticmethod
    def state_matrix(state):
        """
        Formats a State Matrix to a properly formatted list.

        @param state: State Matrix
        @return: Formatted State Matrix
        """
        new_state = []
        for x in range(4):
            new_state += [state[0 + x], state[4 + x], state[8 + x], state[12 + x]]
        return new_state

    @staticmethod
    def inv_state_matrix(state):
        """
        Preform the inverse of the State matrix method.

        @param state: State Matrix
        @return: Reverted State Matrix
        """
        columns = [state[x:x + 4] for x in range(0, 16, 4)]
        new_state = []
        for x in range(4):
            new_state += [columns[0][x], columns[1][x], columns[2][x], columns[3][x]]
        return new_state

    @staticmethod
    def add_round_key(state, key):
        """
        Round Key is added to the State using an XOR operation.

        @param state: State Matrix
        @param key: Round Key
        @return: Hex values of XOR operation
        """
        return [state[x] ^ key[x] for x in range(16)]

    def galois(self, a, b):
        """
        Galois multiplication of 8 bit characters a and b.

        @param a: State Matrix col or row
        @param b: Fixed number
        @return: Galois field GF(2^8)
        """
        if a != 0 and b != 0:
            return self.expbox[(self.lnbox[a] + self.lnbox[b]) % 0xff]
        return 0

    def sub_word(self, byte):
        """
        Key Expansion routine that takes a four-byte
        input word and applies an S-box substitution.

        @param byte: Output from the circular byte left shift
        @return: Substituted bytes through sbox
        """
        return ((self.sbox[(byte >> 24 & 0xff)] << 24) + (self.sbox[(byte >> 16 & 0xff)] << 16) +
                (self.sbox[(byte >> 8 & 0xff)] << 8) + self.sbox[byte & 0xff])

    def shift_rows(self, state):
        """
        Changes the State by cyclically shifting the last
        three rows of the State by different offsets.

        @param state: State Matrix
        @return: Shifted state by offsets [0, 1, 2, 3]
        """
        offset = 0
        for x in range(0, 16, 4):
            state[x:x + 4] = state[x:x + 4][offset:] + state[x:x + 4][:offset]
            offset += 1
        return state

    def inv_shift_rows(self, state):
        """
        Preform the inverse of the shift rows method.

        @param state: State Matrix
        @return: Shifted state by offsets [0, 1, 2, 3]
        """
        offset = 0
        state = self.inv_state_matrix(state)
        for x in range(0, 16, 4):
            state[x:x + 4] = state[x:x + 4][offset:] + state[x:x + 4][:offset]
            offset -= 1
        return self.state_matrix(state)

    def sub_bytes(self, state):
        """
        Transforms the State Matrix using a nonlinear byte S-box
        that operates on each of the State bytes independently.

        @param state: State matrix input
        @return: Byte substitution from the state matrix
        """
        return [self.sbox[state[x]] for x in range(16)]

    def inv_sub_bytes(self, state):
        """
        Preform the inverse of the sub bytes method.

        @param state: State matrix input
        @return: Byte substitution from the state matrix
        """
        return [self.rsbox[state[x]] for x in range(16)]

    def mix_columns(self, state):
        """
        Operates on the State column-by-column, treating each column as
        a four-term polynomial. The columns are considered as polynomials
        over GF(2^8) and multiplied modulo x^4 + 1 with a fixed polynomial a(x).

        @param state: State Matrix input
        @return: Byte substitution from the state matrix
        """
        columns = [state[x:x + 4] for x in range(0, 16, 4)]
        row = [0, 3, 2, 1]
        col = 0
        output = []
        for _ in range(4):
            for _ in range(4):
                output.append(
                    self.galois(columns[row[0]][col], 2) ^
                    self.galois(columns[row[1]][col], 1) ^
                    self.galois(columns[row[2]][col], 1) ^
                    self.galois(columns[row[3]][col], 3))
                row = [row[-1]] + row[:-1]
            col += 1
        return self.state_matrix(output)

    def inv_mix_columns(self, state):
        """
        Preform the inverse of the mix columns method.

        @param state: State Matrix input
        @return: Byte substitution from the state matrix
        """
        state = self.state_matrix(state)
        columns = [state[x:x + 4] for x in range(0, 16, 4)]
        row = [0, 3, 2, 1]
        col = 0
        output = []
        for _ in range(4):
            for _ in range(4):
                output.append(
                    self.galois(columns[row[0]][col], 14) ^
                    self.galois(columns[row[1]][col], 9) ^
                    self.galois(columns[row[2]][col], 13) ^
                    self.galois(columns[row[3]][col], 11))
                row = [row[-1]] + row[:-1]
            col += 1
        return output

    def cipher(self, expanded_key, data):
        """
        At the start of the Cipher, the input is copied to the
        State Matrix. After an initial Round Key addition, the
        State Matrix is transformed by implementing a round function
        10, 12, or 14 times (depending on the key length), with the final
        round differing slightly from the first Nr -1 rounds. The final
        State Matrix is then copied as the output.

        @param expanded_key: The expanded key schedule
        @param data: Data to encrypt
        @return: Encrypted data
        """
        state = self.add_round_key(self.state_matrix(data), expanded_key[0])

        for r in range(self.Nr - 1):
            state = self.sub_bytes(state)
            state = self.shift_rows(state)
            state = self.mix_columns(state)
            state = self.add_round_key(state, expanded_key[r + 1])

        state = self.sub_bytes(state)
        state = self.shift_rows(state)
        state = self.add_round_key(state, expanded_key[self.Nr])
        return self.inv_state_matrix(state)

    def inv_cipher(self, expanded_key, data):
        """
        Preform the inverse of the cipher method.

        @param expanded_key: The expanded key schedule
        @param data: Data to decrypt
        @return: Decrypted data
        """
        state = self.add_round_key(data, expanded_key[self.Nr])

        for r in range(self.Nr - 1):
            state = self.inv_shift_rows(state)
            state = self.inv_sub_bytes(state)
            state = self.add_round_key(state, expanded_key[-(r + 2)])
            state = self.inv_mix_columns(state)

        state = self.inv_shift_rows(state)
        state = self.inv_sub_bytes(state)
        state = self.add_round_key(state, expanded_key[0])
        return state

    def expand_key(self, key):
        """
        Takes the Cipher Key and performs a Key Expansion routine to
        generate a key schedule thus generating a total of Nb (Nr + 1) words.

        @param key: Cipher Key
        @return: Expanded Cipher Keys
        """
        w = [int(key[y:y + 8], 16) for y in range(0, len(key), 8)]

        i = self.Nk
        while i < self.Nb * (self.Nr + 1):
            temp = w[i - 1]
            if i % self.Nk == 0:
                temp = self.sub_word(self.rot_word(temp)) ^ (self.rcon[i // self.Nk] << 24)
            elif self.Nk > 6 and i % self.Nk == 4:
                temp = self.sub_word(temp)
            w.append(w[i - self.Nk] ^ temp)
            i += 1

        new_state = []
        for x in range(0, len(w), 4):
            state = []
            for y in range(4):
                state += [w[x + y] >> 24 & 0xff, w[x + y] >> 16 & 0xff, w[x+y] >> 8 & 0xff, w[x+y] & 0xff]
            new_state.append(self.state_matrix(state))
        return new_state

    def inv_expand_key(self, key):
        """
        Preform the inverse of the key expansion method.

        @param key: Cipher Key
        @return: Expanded Cipher Keys
        """
        return [self.inv_state_matrix(x) for x in self.expand_key(key)]

    def encrypt(self, data):
        """
        Encryption method.

        @param data: Data to be encrypted
        @return: Encrypted data
        """
        expanded_key = self.expand_key(self.key)
        if self.iv:
            return self.cbc_encrypt(data, expanded_key)
        else:
            return self.ecb_encrypt(data, expanded_key)

    def decrypt(self, data):
        """
        Decryption method.

        @param data: Data to be decrypted
        @return: Decrypted data
        """
        expanded_key = self.inv_expand_key(self.key)
        if self.iv:
            return self.cbc_decrypt(data, expanded_key)
        else:
            return self.ecb_decrypt(data, expanded_key)

    def cbc_encrypt(self, data, expanded_key):
        """
        Encrypt data using the Cipher Block Chaining (CBC) mode.

        @param data: Data to be encrypted
        @param expanded_key: The AES expanded key set
        @return: Encrypted data
        """
        if isinstance(data, str):
            pad = self.pad(bytes(data, 'utf-8'))
            blocks = [binascii.unhexlify(self.iv.encode())]
            for x in [pad[y:y + 16] for y in range(0, len(pad), 16)]:
                blocks.append(self.cipher(expanded_key, self.xor(blocks[-1], x)))
            return binascii.hexlify(bytes(y for x in blocks[1:] for y in x)).decode()
        elif isinstance(data, bytes):
            pad = self.pad(data)
            blocks = [binascii.unhexlify(self.iv.encode())]
            for x in [pad[y:y + 16] for y in range(0, len(pad), 16)]:
                blocks.append(self.cipher(expanded_key, self.xor(blocks[-1], x)))
            return bytes(y for x in blocks[1:] for y in x)
        else:
            raise AttributeError("Data must be of type 'str' or 'bytes'.")

    def cbc_decrypt(self, data, expanded_key):
        """
        Decrypt data using the Cipher Block Chaining (CBC) mode.

        @param data: Data to be decrypted
        @param expanded_key: The AES expanded key set
        @return: Decrypted data
        """
        if isinstance(data, str):
            data = [binascii.unhexlify(data[y:y + 32]) for y in range(0, len(data), 32)]
            blocks = [binascii.unhexlify(self.iv.encode())] + data
            return ''.join(chr(x) for x in self.unpad([y for x in [x for x in [self.xor(self.inv_cipher(
                    expanded_key, data[x]), blocks[x]) for x in range(len(data))]] for y in x]))
        elif isinstance(data, bytes):
            data = [data[y:y + 16] for y in range(0, len(data), 16)]
            blocks = [binascii.unhexlify(self.iv.encode())] + data
            return bytes(self.unpad([y for x in [x for x in [self.xor(self.inv_cipher(
                    expanded_key, data[x]), blocks[x]) for x in range(len(data))]] for y in x]))
        else:
            raise AttributeError("Data must be of type 'str' or 'bytes'.")

    def ecb_encrypt(self, data, expanded_key):
        """
        Encrypt data using the Electronic Codebook (ECB) mode.

        @param data: Data to be encrypted
        @param expanded_key: The AES expanded key set
        @return: Encrypted data
        """
        if isinstance(data, str):
            pad = self.pad(bytes(data, 'utf-8'))
            return binascii.hexlify(bytes(y for x in [self.cipher(expanded_key, x) for x in [
                    pad[y:y + 16] for y in range(0, len(pad), 16)]] for y in x)).decode()
        elif isinstance(data, bytes):
            pad = self.pad(data)
            return bytes(y for x in [self.cipher(expanded_key, x) for x in [
                    pad[y:y + 16] for y in range(0, len(pad), 16)]] for y in x)
        else:
            raise AttributeError("Data must be of type 'str' or 'bytes'.")

    def ecb_decrypt(self, data, expanded_key):
        """
        Decrypt data using the Electronic Codebook (ECB) mode.

        @param data: Data to be decrypted
        @param expanded_key: The AES expanded key set
        @return: Decrypted data
        """
        if isinstance(data, str):
            data = binascii.unhexlify(data)
            return ''.join(chr(x) for x in self.unpad([y for x in [self.inv_cipher(expanded_key, x) for x in [
                    data[y:y + 16] for y in range(0, len(data), 16)]] for y in x]))
        elif isinstance(data, bytes):
            return self.unpad(bytes(y for x in [self.inv_cipher(expanded_key, x) for x in [
                    data[y:y + 16] for y in range(0, len(data), 16)]] for y in x))
        else:
            raise AttributeError("Data must be of type 'str' or 'bytes'.")
