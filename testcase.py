from unittest import TestCase, TestProgram
from random import randrange, choice
from string import ascii_letters
from os import urandom
from aes import AES


class TestAesEcb(TestCase):
    def test_str_128_bit(self):
        key = 0x000102030405060708090a0b0c0d0e0f
        data = "Hello World!"

        aes = AES(key)
        cyphertext = aes.encrypt(data)
        plaintext = aes.decrypt(cyphertext)

        self.assertEqual(data, plaintext)

    def test_str_192_bit(self):
        key = 0x000102030405060708090a0b0c0d0e0f1011121314151617
        data = "Hello World!"

        aes = AES(key)
        cyphertext = aes.encrypt(data)
        plaintext = aes.decrypt(cyphertext)

        self.assertEqual(data, plaintext)

    def test_str_256_bit(self):
        key = 0x000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f
        data = "Hello World!"

        aes = AES(key)
        cyphertext = aes.encrypt(data)
        plaintext = aes.decrypt(cyphertext)

        self.assertEqual(data, plaintext)

    def test_byte_str_128_bit(self):
        key = 0x000102030405060708090a0b0c0d0e0f
        data = b'Hello World!'

        aes = AES(key)
        cyphertext = aes.encrypt(data)
        plaintext = aes.decrypt(cyphertext)

        self.assertEqual(data, plaintext)

    def test_byte_str_192_bit(self):
        key = 0x000102030405060708090a0b0c0d0e0f1011121314151617
        data = b'Hello World!'

        aes = AES(key)
        cyphertext = aes.encrypt(data)
        plaintext = aes.decrypt(cyphertext)

        self.assertEqual(data, plaintext)

    def test_byte_str_256_bit(self):
        key = 0x000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f
        data = b'Hello World!'

        aes = AES(key)
        cyphertext = aes.encrypt(data)
        plaintext = aes.decrypt(cyphertext)

        self.assertEqual(data, plaintext)

    def test_str_random_128_bit(self):
        key = ''.join(choice(ascii_letters) for _ in range(randrange(16)))
        data = ''.join(choice(ascii_letters) for _ in range(randrange(64)))

        aes = AES(key)
        cyphertext = aes.encrypt(data)
        plaintext = aes.decrypt(cyphertext)

        self.assertEqual(data, plaintext)

    def test_str_random_192_bit(self):
        key = ''.join(choice(ascii_letters) for _ in range(randrange(17, 24)))
        data = ''.join(choice(ascii_letters) for _ in range(randrange(64)))

        aes = AES(key)
        cyphertext = aes.encrypt(data)
        plaintext = aes.decrypt(cyphertext)

        self.assertEqual(data, plaintext)

    def test_str_random_256_bit(self):
        key = ''.join(choice(ascii_letters) for _ in range(randrange(25, 32)))
        data = ''.join(choice(ascii_letters) for _ in range(randrange(64)))

        aes = AES(key)
        cyphertext = aes.encrypt(data)
        plaintext = aes.decrypt(cyphertext)

        self.assertEqual(data, plaintext)

    def test_hex_str_random_128_bit(self):
        key = randrange(0xffffffffffffffffffffffffffffffff)
        data = urandom(randrange(64))

        aes = AES(key)
        cyphertext = aes.encrypt(data)
        plaintext = aes.decrypt(cyphertext)

        self.assertEqual(data, plaintext)

    def test_hex_str_random_192_bit(self):
        key = randrange(0xfffffffffffffffffffffffffffffffff,
                               0xffffffffffffffffffffffffffffffffffffffffffffffff)
        data = urandom(randrange(64))

        aes = AES(key)
        cyphertext = aes.encrypt(data)
        plaintext = aes.decrypt(cyphertext)

        self.assertEqual(data, plaintext)

    def test_hex_str_random_256_bit(self):
        key = randrange(0xfffffffffffffffffffffffffffffffffffffffffffffffff,
                               0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff)
        data = urandom(randrange(64))

        aes = AES(key)
        cyphertext = aes.encrypt(data)
        plaintext = aes.decrypt(cyphertext)

        self.assertEqual(data, plaintext)


class TestAesCbc(TestCase):
    def test_str_128_bit(self):
        key = 0x000102030405060708090a0b0c0d0e0f
        iv = 0x000102030405060708090a0b0c0d0e0f
        data = "Hello World!"

        aes = AES(key, iv)
        cyphertext = aes.encrypt(data)
        plaintext = aes.decrypt(cyphertext)

        self.assertEqual(data, plaintext)

    def test_str_192_bit(self):
        key = 0x000102030405060708090a0b0c0d0e0f1011121314151617
        iv = 0x000102030405060708090a0b0c0d0e0f
        data = "Hello World!"

        aes = AES(key, iv)
        cyphertext = aes.encrypt(data)
        plaintext = aes.decrypt(cyphertext)

        self.assertEqual(data, plaintext)

    def test_str_256_bit(self):
        key = 0x000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f
        iv = 0x000102030405060708090a0b0c0d0e0f
        data = "Hello World!"

        aes = AES(key, iv)
        cyphertext = aes.encrypt(data)
        plaintext = aes.decrypt(cyphertext)

        self.assertEqual(data, plaintext)

    def test_byte_str_128_bit(self):
        key = 0x000102030405060708090a0b0c0d0e0f
        iv = 0x000102030405060708090a0b0c0d0e0f
        data = b'Hello World!'

        aes = AES(key, iv)
        cyphertext = aes.encrypt(data)
        plaintext = aes.decrypt(cyphertext)

        self.assertEqual(data, plaintext)

    def test_byte_str_192_bit(self):
        key = 0x000102030405060708090a0b0c0d0e0f1011121314151617
        iv = 0x000102030405060708090a0b0c0d0e0f
        data = b'Hello World!'

        aes = AES(key, iv)
        cyphertext = aes.encrypt(data)
        plaintext = aes.decrypt(cyphertext)

        self.assertEqual(data, plaintext)

    def test_byte_str_256_bit(self):
        key = 0x000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f
        iv = 0x000102030405060708090a0b0c0d0e0f
        data = b'Hello World!'

        aes = AES(key, iv)
        cyphertext = aes.encrypt(data)
        plaintext = aes.decrypt(cyphertext)

        self.assertEqual(data, plaintext)

    def test_str_random_128_bit(self):
        key = ''.join(choice(ascii_letters) for _ in range(randrange(16)))
        iv = ''.join(choice(ascii_letters) for _ in range(randrange(16)))
        data = ''.join(choice(ascii_letters) for _ in range(randrange(64)))

        aes = AES(key, iv)
        cyphertext = aes.encrypt(data)
        plaintext = aes.decrypt(cyphertext)

        self.assertEqual(data, plaintext)

    def test_str_random_192_bit(self):
        key = ''.join(choice(ascii_letters) for _ in range(randrange(17, 24)))
        iv = ''.join(choice(ascii_letters) for _ in range(randrange(16)))
        data = ''.join(choice(ascii_letters) for _ in range(randrange(64)))

        aes = AES(key, iv)
        cyphertext = aes.encrypt(data)
        plaintext = aes.decrypt(cyphertext)

        self.assertEqual(data, plaintext)

    def test_str_random_256_bit(self):
        key = ''.join(choice(ascii_letters) for _ in range(randrange(25, 32)))
        iv = ''.join(choice(ascii_letters) for _ in range(randrange(16)))
        data = ''.join(choice(ascii_letters) for _ in range(randrange(64)))

        aes = AES(key, iv)
        cyphertext = aes.encrypt(data)
        plaintext = aes.decrypt(cyphertext)

        self.assertEqual(data, plaintext)

    def test_hex_str_random_128_bit(self):
        key = randrange(0xffffffffffffffffffffffffffffffff)
        iv = randrange(0xffffffffffffffffffffffffffffffff)
        data = urandom(randrange(64))

        aes = AES(key, iv)
        cyphertext = aes.encrypt(data)
        plaintext = aes.decrypt(cyphertext)

        self.assertEqual(data, plaintext)

    def test_hex_str_random_192_bit(self):
        key = randrange(0xfffffffffffffffffffffffffffffffff,
                               0xffffffffffffffffffffffffffffffffffffffffffffffff)
        iv = randrange(0xffffffffffffffffffffffffffffffff)
        data = urandom(randrange(64))

        aes = AES(key, iv)
        cyphertext = aes.encrypt(data)
        plaintext = aes.decrypt(cyphertext)

        self.assertEqual(data, plaintext)

    def test_hex_str_random_256_bit(self):
        key = randrange(0xfffffffffffffffffffffffffffffffffffffffffffffffff,
                               0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff)
        iv = randrange(0xffffffffffffffffffffffffffffffff)
        data = urandom(randrange(64))

        aes = AES(key, iv)
        cyphertext = aes.encrypt(data)
        plaintext = aes.decrypt(cyphertext)

        self.assertEqual(data, plaintext)


if __name__ == '__main__':
    TestProgram()
