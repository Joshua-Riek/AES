# AES-128bit
My implementation  of ASE 128bit encryption written in pure Python! This features the ability to use ECB mode and CBC mode along with various types of input data.


## ECB Mode
The simplest of the encryption modes is the Electronic Codebook (ECB) mode. 

The message is divided into blocks, and each block is encrypted separately.
```Python
# A simple example of encrypting an Hex string with ECB mode!

# Test vector 128-bit key
key = '000102030405060708090a0b0c0d0e0f'
# Hex string to encrypt!
data = '00112233445566778899aabbccddeeff'
# Set AES mode of operation (ECB, w/ hex input)
aes = AES(mode='ecb', input_type='hex')
# Encrypt data with your key
cyphertext = aes.encryption(data, key)
# Decrypt data with the same key
plaintext = aes.decryption(cyphertext, key)
```

## CBC Mode
In CBC mode, each block of plaintext is XORed with the previous ciphertext block before being encrypted. This can be denoted as:

Encryption:` Ci = Ek(Pi xor C(i-1)) and C0 = IV`

Decryption: `Pi = Dk(Ci) xor C(i-1) and C0 = IV`

```Python
# A simple example of encrypting an random data with CBC mode!

# Test vector 128-bit key
key = '000102030405060708090a0b0c0d0e0f'
# Random data to encrypt
data = data = os.urandom(254)
# Set AES mode of operation (CBC, w/ data input)
aes = AES(mode='cbc', input_type='data', iv='000102030405060708090A0B0C0D0E0F')
# Encrypt data with your key
cyphertext = aes.encryption(data, key)
# Decrypt data with the same key
plaintext = aes.decryption(cyphertext, key)
```
