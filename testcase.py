import unittest
import random
import string
import os
from aes import AES


class TestAesEcb(unittest.TestCase):
    def test_data(self):
        key = 0x000102030405060708090a0b0c0d0e0f
        data = b'Hello World!'

        aes = AES(mode='ecb')
        cyphertext = aes.encryption(data, key)
        plaintext = aes.decryption(cyphertext, key)

        self.assertEqual(data, plaintext)

    def test_random_data(self):
        key = random.randrange(0xffffffffffffffffffffffffffffffff)
        data = os.urandom(64)

        aes = AES(mode='ecb')
        cyphertext = aes.encryption(data, key)
        plaintext = aes.decryption(cyphertext, key)

        self.assertEqual(data, plaintext)

    def test_str(self):
        key = 0x000102030405060708090a0b0c0d0e0f
        data = 'Hello World!'

        aes = AES(mode='ecb')
        cyphertext = aes.encryption(data, key)
        plaintext = aes.decryption(cyphertext, key)

        self.assertEqual(data, plaintext)

    def test_random_str(self):
        key = random.randrange(0xffffffffffffffffffffffffffffffff)
        data = ''.join(random.choice(string.ascii_letters) for _ in range(64))

        aes = AES(mode='ecb')
        cyphertext = aes.encryption(data, key)
        plaintext = aes.decryption(cyphertext, key)

        self.assertEqual(data, plaintext)


class TestAesCbc(unittest.TestCase):
    def test_data(self):
        key = 0x000102030405060708090a0b0c0d0e0f
        iv = 0x000102030405060708090a0b0c0d0e0f
        data = b'Hello World!'

        aes = AES(mode='cbc', iv=iv)
        cyphertext = aes.encryption(data, key)
        plaintext = aes.decryption(cyphertext, key)

        self.assertEqual(data, plaintext)

    def test_random_data(self):
        key = random.randrange(0xffffffffffffffffffffffffffffffff)
        iv = random.randrange(0xffffffffffffffffffffffffffffffff)
        data = os.urandom(64)

        aes = AES(mode='cbc', iv=iv)
        cyphertext = aes.encryption(data, key)
        plaintext = aes.decryption(cyphertext, key)

        self.assertEqual(data, plaintext)

    def test_str(self):
        key = 0x000102030405060708090a0b0c0d0e0f
        iv = 0x000102030405060708090a0b0c0d0e0f
        data = 'Hello World!'

        aes = AES(mode='cbc', iv=iv)
        cyphertext = aes.encryption(data, key)
        plaintext = aes.decryption(cyphertext, key)

        self.assertEqual(data, plaintext)

    def test_random_str(self):
        key = random.randrange(0xffffffffffffffffffffffffffffffff)
        iv = random.randrange(0xffffffffffffffffffffffffffffffff)
        data = ''.join(random.choice(string.ascii_letters) for _ in range(64))

        aes = AES(mode='cbc', iv=iv)
        cyphertext = aes.encryption(data, key)
        plaintext = aes.decryption(cyphertext, key)

        self.assertEqual(data, plaintext)


if __name__ == '__main__':
    unittest.TestProgram()
