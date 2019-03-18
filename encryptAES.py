from Crypto.Cipher import AES
from Crypto import Random
import os
import sys
import os.path
from os import listdir
from os.path import isfile, join
import time

AES_128 = 128
class Encryptor:
    def __init__(self, key):
        print('AES.block_size', key)
        self.key = key

    def pad(self, s):
        return s + b"\0" * (AES.block_size - len(s) % AES.block_size)

    def encrypt(self, message, key, key_size=128):
        message = self.pad(message)
        iv = Random.new().read(AES.block_size)
        cipher = AES.new(key, AES.MODE_CBC, iv)
        return iv + cipher.encrypt(message)

    def encrypt_file(self, file_name, file_three, encrypted_aes_key):
        with open(file_name, 'rb') as fo:
            plaintext = fo.read()
        enc = self.encrypt(plaintext, self.key)
        print('writing cipher text ', enc);
        with open(file_three, 'wb') as fo:
            fo.write(enc)

    def decrypt(self, ciphertext, key):
        iv = ciphertext[:AES.block_size]
        cipher = AES.new(key, AES.MODE_CBC, iv)
        plaintext = cipher.decrypt(ciphertext[AES.block_size:])
        return plaintext.rstrip(b"\0")

    def decrypt_file(self, file_name, file_three, decrypted_aes_key):
        with open(file_name, 'rb') as fo:
            ciphertext = fo.read()
        dec = self.decrypt(ciphertext, self.key)
        print('writing text ', dec);
        with open(file_three, 'wb') as fo:
            fo.write(dec)



enc = Encryptor(Random.new().read(AES_128))
clear = lambda: os.system('cls')
isEncy = sys.argv[1] == '-e' ? True : False;
file_one = sys.argv[2]
file_two = sys.argv[3]
file_three = sys.argv[4]
if(isEncy):
    with open(file_one, 'rb') as fo:
        text = fo.read()
        publicKey = [int(x) for x in next(fo).split("#")]
        encrypted_aes_key = encryptRSA(publicKey, self.key)
        self.encrypt_file(file_two, file_three, encrypted_aes_key)
else :
    with open(file_one, 'rb') as fo:
        text = fo.read()
        pirvateKey = [int(x) for x in next(fo).split("#")]
        decrypted_aes_key = decryptRSA(pirvateKey, self.key)
        self.encrypt_file(file_two, file_three, decrypted_aes_key)

print("Process is done ")