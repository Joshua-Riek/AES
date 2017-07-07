import unittest
from aes import AES
import os


class Test_aes_ecb(unittest.TestCase):
    # AES ECB Mode Testing for hex string.
    def test_hex(self):
        # Test vector 128-bit key
        key = '000102030405060708090a0b0c0d0e0f'
        # Aes mode of operation
        aes = AES(mode='ecb', input_type='hex')
        # Encrypt data with your key
        cyphertext = aes.encryption('00112233445566778899aabbccddeeff', key)
        # Decrypt data with the same key
        plaintext = aes.decryption(cyphertext, key)
        # Ensure that data is equal to plaintext
        self.assertEqual('00112233445566778899aabbccddeeff', plaintext)

    # AES ECB Mode Testing for ascii string.
    def test_str(self):
        # Test vector 128-bit key
        key = '000102030405060708090a0b0c0d0e0f'
        # Ascii string test
        aes = AES(mode='ecb', input_type='text')
        # Encrypt data with your key
        cyphertext = aes.encryption('root', key)
        # Decrypt data with the same key
        plaintext = aes.decryption(cyphertext, key)
        # Ensure that data is equal to plaintext
        self.assertEqual('root', plaintext)

    # AES ECB Mode Testing for raw data.
    def test_data(self):
        # Test vector 128-bit key
        key = '000102030405060708090a0b0c0d0e0f'
        # Data stream test
        aes = AES(mode='ecb', input_type='data')
        # Random data to encrypt
        data = os.urandom(64)
        # Encrypt data with your key
        cyphertext = aes.encryption(data, key)
        # Decrypt data with the same key
        plaintext = aes.decryption(cyphertext, key)
        # Ensure that data is equal to plaintext
        self.assertEqual(data, plaintext)


class Test_aes_cbc(unittest.TestCase):
    # AES CBC Mode Testing for hex string.
    def test_hex(self):
        # Test vector 128-bit key
        key = '000102030405060708090a0b0c0d0e0f'
        # Data stream test
        aes = AES(mode='cbc', input_type='hex', iv='000102030405060708090A0B0C0D0E0F')
        # Random data to encrypt
        data = ['6bc1bee22e409f96e93d7e117393172a']
        # Encrypt data with your key
        cyphertext = aes.encryption(data, key)
        # Decrypt data with the same key
        plaintext = aes.decryption(cyphertext, key)
        # Ensure that data is equal to plaintext
        self.assertEqual(data, plaintext)

    # AES CBC Mode Testing for raw data.
    def test_data(self):
        # Test vector 128-bit key
        key = '000102030405060708090a0b0c0d0e0f'
        # Raw data stream test
        aes = AES(mode='cbc', input_type='data', iv='000102030405060708090A0B0C0D0E0F')
        # Random data to encrypt
        data = os.urandom(254)
        # Encrypt data with your key
        cyphertext = aes.encryption(data, key)
        # Decrypt data with the same key
        plaintext = aes.decryption(cyphertext, key)
        # Ensure that data is equal to plaintext
        self.assertEqual(data, plaintext)


if __name__ == '__main__':
    unittest.TestProgram()

