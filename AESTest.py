from Crypto import Random
from Crypto.Cipher import AES
import os
import os.path
from os import listdir
from os.path import isfile, join
import time
import sys


class Encryptor:
    def __init__(self, key):
        self.key = key

    def pad(self, s):
        return s + b"\0" * (AES.block_size - len(s) % AES.block_size)

    def encrypt(self, message, key, key_size=256):
        message = self.pad(message)
        iv = Random.new().read(AES.block_size)
        cipher = AES.new(key, AES.MODE_CBC, iv)
        return iv + cipher.encrypt(message)

    def encrypt_file(self, file_txt, file_cip):
        with open(file_txt, 'rb') as fo:
            plaintext = fo.read()
        enc = self.encrypt(plaintext, self.key)
        print('writing contentn', enc)
        print('writing key ', self.key)

        with open(file_cip, 'wb') as fo:
            fo.write(enc)
        with open(file_cip, 'ab') as fo:
            fo.write(self.key)        



    def decrypt(self, ciphertext, key):
        iv = ciphertext[:AES.block_size]
        cipher = AES.new(key, AES.MODE_CBC, iv)
        
        plaintext = cipher.decrypt(ciphertext[AES.block_size:])
        return plaintext.rstrip(b"\0")

    def decrypt_file(self, file_cip, file_txt, key):
        
        with open(file_cip, 'rb') as fo:
            ciphertext = fo.read()
  
        #print('Content returned ', ciphertext[:-32])   
        #print('Key returned ', ciphertext[-32:])
        plaintext = self.decrypt(ciphertext[:-32], ciphertext[-32:])
        print('plaintext', plaintext)
        with open(file_txt, 'wb') as fo:
            fo.write(plaintext)


keyK = os.urandom(32)
enc = Encryptor(keyK)
clear = lambda: os.system('cls')


print('First arg is ', sys.argv[1])

if(sys.argv[1] == '-e'):
    isEncy = True

file_one = sys.argv[2]
file_two = sys.argv[3]
file_three = sys.argv[4]
#/crypt.py -e bob.pub message.txt message.cip
if(isEncy):
    with open(file_one, 'r') as fo:
        text = fo.read()
        #encrypted_aes_key = enc.encryptRSA(text)
        enc.encrypt_file(file_three, file_two)
        enc.decrypt_file(file_two, file_three, keyK)
#./crypt.py -d bob.prv message.cip message.txt        
else :
    with open(file_one, 'r') as fo:
        text = fo.read()
        enc.decrypt_file(cipher, file_three, enc_key)

print("Process is done ")