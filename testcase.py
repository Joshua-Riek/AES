import unittest
import random
import string
import os
from aes import AES


class TestAesEcb(unittest.TestCase):
    def test_data_128_bit(self):
        key = 0x000102030405060708090a0b0c0d0e0f
        data = b'Hello World!'

        aes = AES(key)
        cyphertext = aes.encrypt(data)
        plaintext = aes.decrypt(cyphertext)

        self.assertEqual(data, plaintext)

    def test_data_192_bit(self):
        key = 0x000102030405060708090a0b0c0d0e0f1011121314151617
        data = b'Hello World!'

        aes = AES(key)
        cyphertext = aes.encrypt(data)
        plaintext = aes.decrypt(cyphertext)

        self.assertEqual(data, plaintext)

    def test_data_256_bit(self):
        key = 0x000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f
        data = b'Hello World!'

        aes = AES(key)
        cyphertext = aes.encrypt(data)
        plaintext = aes.decrypt(cyphertext)

        self.assertEqual(data, plaintext)

    def test_random_data_128_bit(self):
        key = random.randrange(0xffffffffffffffffffffffffffffffff)
        data = os.urandom(random.randrange(64))

        aes = AES(key)
        cyphertext = aes.encrypt(data)
        plaintext = aes.decrypt(cyphertext)

        self.assertEqual(data, plaintext)

    def test_random_data_192_bit(self):
        key = random.randrange(0xffffffffffffffffffffffffffffffffffffffffffffffff)
        data = os.urandom(random.randrange(64))

        aes = AES(key)
        cyphertext = aes.encrypt(data)
        plaintext = aes.decrypt(cyphertext)

        self.assertEqual(data, plaintext)

    def test_random_data_256_bit(self):
        key = random.randrange(0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff)
        data = os.urandom(random.randrange(64))

        aes = AES(key)
        cyphertext = aes.encrypt(data)
        plaintext = aes.decrypt(cyphertext)

        self.assertEqual(data, plaintext)

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

    def test_random_str_128_bit(self):
        key = random.randrange(0xffffffffffffffffffffffffffffffff)
        data = ''.join(random.choice(string.ascii_letters) for _ in range(random.randrange(64)))

        aes = AES(key)
        cyphertext = aes.encrypt(data)
        plaintext = aes.decrypt(cyphertext)

        self.assertEqual(data, plaintext)

    def test_random_str_192_bit(self):
        key = random.randrange(0xffffffffffffffffffffffffffffffffffffffffffffffff)
        data = ''.join(random.choice(string.ascii_letters) for _ in range(random.randrange(64)))

        aes = AES(key)
        cyphertext = aes.encrypt(data)
        plaintext = aes.decrypt(cyphertext)

        self.assertEqual(data, plaintext)

    def test_random_str_256_bit(self):
        key = random.randrange(0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff)
        data = ''.join(random.choice(string.ascii_letters) for _ in range(random.randrange(64)))

        aes = AES(key)
        cyphertext = aes.encrypt(data)
        plaintext = aes.decrypt(cyphertext)

        self.assertEqual(data, plaintext)


class TestAesCbc(unittest.TestCase):
    def test_data_128_bit(self):
        key = 0x000102030405060708090a0b0c0d0e0f
        iv = 0x000102030405060708090a0b0c0d0e0f
        data = b'Hello World!'

        aes = AES(key, iv)
        cyphertext = aes.encrypt(data)
        plaintext = aes.decrypt(cyphertext)

        self.assertEqual(data, plaintext)

    def test_data_192_bit(self):
        key = 0x000102030405060708090a0b0c0d0e0f1011121314151617
        iv = 0x000102030405060708090a0b0c0d0e0f
        data = b'Hello World!'

        aes = AES(key, iv)
        cyphertext = aes.encrypt(data)
        plaintext = aes.decrypt(cyphertext)

        self.assertEqual(data, plaintext)

    def test_data_256_bit(self):
        key = 0x000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f
        iv = 0x000102030405060708090a0b0c0d0e0f
        data = b'Hello World!'

        aes = AES(key, iv)
        cyphertext = aes.encrypt(data)
        plaintext = aes.decrypt(cyphertext)

        self.assertEqual(data, plaintext)

    def test_random_data_128_bit(self):
        key = random.randrange(0xffffffffffffffffffffffffffffffff)
        iv = random.randrange(0xffffffffffffffffffffffffffffffff)
        data = os.urandom(random.randrange(64))

        aes = AES(key, iv)
        cyphertext = aes.encrypt(data)
        plaintext = aes.decrypt(cyphertext)

        self.assertEqual(data, plaintext)

    def test_random_data_192_bit(self):
        key = random.randrange(0xffffffffffffffffffffffffffffffffffffffffffffffff)
        iv = random.randrange(0xffffffffffffffffffffffffffffffff)
        data = os.urandom(random.randrange(64))

        aes = AES(key, iv)
        cyphertext = aes.encrypt(data)
        plaintext = aes.decrypt(cyphertext)

        self.assertEqual(data, plaintext)

    def test_random_data_256_bit(self):
        key = random.randrange(0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff)
        iv = random.randrange(0xffffffffffffffffffffffffffffffff)
        data = os.urandom(random.randrange(64))

        aes = AES(key, iv)
        cyphertext = aes.encrypt(data)
        plaintext = aes.decrypt(cyphertext)

        self.assertEqual(data, plaintext)

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

    def test_random_str_128_bit(self):
        key = random.randrange(0xffffffffffffffffffffffffffffffff)
        iv = random.randrange(0xffffffffffffffffffffffffffffffff)
        data = ''.join(random.choice(string.ascii_letters) for _ in range(random.randrange(64)))

        aes = AES(key, iv)
        cyphertext = aes.encrypt(data)
        plaintext = aes.decrypt(cyphertext)

        self.assertEqual(data, plaintext)

    def test_random_str_192_bit(self):
        key = random.randrange(0xffffffffffffffffffffffffffffffffffffffffffffffff)
        iv = random.randrange(0xffffffffffffffffffffffffffffffff)
        data = ''.join(random.choice(string.ascii_letters) for _ in range(random.randrange(64)))

        aes = AES(key, iv)
        cyphertext = aes.encrypt(data)
        plaintext = aes.decrypt(cyphertext)

        self.assertEqual(data, plaintext)

    def test_random_str_256_bit(self):
        key = random.randrange(0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff)
        iv = random.randrange(0xffffffffffffffffffffffffffffffff)
        data = ''.join(random.choice(string.ascii_letters) for _ in range(random.randrange(64)))

        aes = AES(key, iv)
        cyphertext = aes.encrypt(data)
        plaintext = aes.decrypt(cyphertext)

        self.assertEqual(data, plaintext)


if __name__ == '__main__':
    unittest.TestProgram()
