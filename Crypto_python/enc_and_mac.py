"""
An illustration of Encrypt and MAC form of Authenticated Encryption with MACs
MAC algorithm: CBC-MAC
Encryption: AES in CBC mode
Note that this is only for illustrative purposes (the script is vulnerable to CBC-MAC forgery and more implementation attacks) 
"""

from Crypto.Cipher import AES
from os import urandom
import binascii

key = urandom(16)
iv = urandom(16)
mac_key = urandom(16)

blocksize = 16

def pad(input_str, blocksize):
    pad_len = blocksize - len(input_str) % blocksize
    return input_str + chr(pad_len) * pad_len

def unpad(input_str):
    pad_len = ord(input_str[-1])
    return input_str[:-pad_len]

def cbc_mac_gen(input_str, iv, mac_key, blocksize):
    input_str = pad(input_str, blocksize)
    obj1 = AES.new(mac_key, AES.MODE_CBC, iv)
    auth_tag = obj1.encrypt(input_str.encode('utf-8'))[-blocksize:]
    return binascii.hexlify(auth_tag).decode('utf-8')

def cbc_mac_auth(input_str, iv, mac_key, blocksize, auth_tag):
    input_str = pad(input_str, blocksize)
    obj1 = AES.new(mac_key, AES.MODE_CBC, iv)
    chk_tag = obj1.encrypt(input_str.encode('utf-8'))[-blocksize:]
    chk_tag_hex = binascii.hexlify(chk_tag).decode('utf-8')
    if chk_tag_hex == auth_tag:
        print("Verification Successful")
        return 1
    else:
        print("Verification Failed")
        return 0

def encrypt(input_str, iv, key, blocksize):
    input_str = pad(input_str, blocksize)
    obj1 = AES.new(key, AES.MODE_CBC, iv)
    ciphertext = obj1.encrypt(input_str.encode('utf-8'))
    return binascii.hexlify(ciphertext).decode('utf-8')

def decrypt(ciphertext, iv, key, blocksize):
    ciphertext = binascii.unhexlify(ciphertext)
    obj1 = AES.new(key, AES.MODE_CBC, iv)
    plaintext = obj1.decrypt(ciphertext).decode('utf-8')
    return unpad(plaintext)

def encrypt_and_mac(input_str, iv, key, mac_key, blocksize):
    return binascii.hexlify(iv).decode('utf-8') + ":" + encrypt(input_str, iv, key, blocksize) + ":" + cbc_mac_gen(input_str, iv, mac_key, blocksize)

def decrypt_and_auth(cookie, key, blocksize, mac_key):
    iv_hex, ciphertext, auth_tag = cookie.split(":")
    iv = binascii.unhexlify(iv_hex)
    input_str = decrypt(ciphertext, iv, key, blocksize)
    if cbc_mac_auth(input_str, iv, mac_key, blocksize, auth_tag):
        return "Plaintext: " + input_str
    else:
        return "Verification failed, so nothing for you!"

# Example usage
str1 = encrypt_and_mac("testplaintext", iv, key, mac_key, 16)
print(str1)
print(decrypt_and_auth(str1, key, 16, mac_key))
