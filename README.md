# Advanced Encryption Standard (AES)
My implementation of AES 256-bit encryption written in pure Python! This features the ability to use ECB mode and CBC mode along with various types of input data.


## ECB Mode
The simplest of the encryption modes is the Electronic Codebook (ECB) mode. 

The message is divided into blocks, and each block is encrypted separately.
```Python
# A simple example of encrypting a string with ECB mode!

key = 0x000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f

aes = AES(key)
cyphertext = aes.encrypt('Hello World!')
plaintext = aes.decrypt(cyphertext) 
```

## CBC Mode
In Cipher Block Chaining (CBC) mode, each block of plaintext is XORed with the previous ciphertext block before being encrypted. This can be denoted as:

Encryption: `Ci = Ek(Pi xor C(i-1)) and C0 = IV`

Decryption: `Pi = Dk(Ci) xor C(i-1) and C0 = IV`

```Python
# A simple example of encrypting bytes with CBC mode!

key = 0x000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f
iv = 0x000102030405060708090a0b0c0d0e0f

aes = AES(key, iv)
cyphertext = aes.encrypt(b'Hello World!')
plaintext = aes.decrypt(cyphertext)
```
