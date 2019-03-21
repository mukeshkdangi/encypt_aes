from Crypto.Cipher import AES
from Crypto import Random
import os
import sys
import os.path
from os import listdir
from os.path import isfile, join

import time
import string
import math
import random

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
        print('plaintext................', plaintext);  
        print(len(self.key))  
        enc = self.encrypt(plaintext,  self.key)
        print('writing cipher text ', enc);
        with open(file_three, 'wb') as fo:
            fo.write(enc)
        with open(file_three, 'w') as fo:
            fo.write(str(",")+ str(encrypted_aes_key)) 

        with open(file_three, 'rb') as fo:
            print(fo.read())    


    def decrypt(self, ciphertext, key):
        iv = ciphertext[:AES.block_size]
        cipher = AES.new(key, AES.MODE_CBC, iv)
        plaintext = cipher.decrypt(ciphertext[AES.block_size:])
        return plaintext.rstrip(b"\0")

    def decrypt_file(self, cipher, file_three, decrypted_aes_key):
        dec = self.decrypt(cipher, decrypted_aes_key)
        print('writing text ', dec);
        with open(file_three, 'wb') as fo:
            fo.write(dec)
           
    def encryptRSA(self, file_text):
        publicKey = [int(x) for x in file_text.split("#")]
        key = publicKey[0]
        n = publicKey[1]
        plaintext = self.key
        #Convert each letter in the plaintext to numbers based on the character using a^b mod m
        list = [str(x) for x in str(n)]
        print('key', key, 'n', n, 'list', list)
        cipher=[pow(ord(char), key, n)  for char in list]

        #Return the array of bytes
        print('returning cipher' , cipher)
        return cipher

  
    def decryptRSA(self, pk, ciphertext):
        #Unpack the key into its components
        key, n = pk
        #Generate the plaintext based on the ciphertext and key using a^b mod m
        plain = [math.pow(chr(char), key,n) for char in ciphertext]
        #Return the array of bytes as a string
        return ''.join(plain)


keyK = os.urandom(32)
print('keyK', keyK)
enc = Encryptor(keyK)
clear = lambda: os.system('cls')
isEncy = False;

print('First arg is ', sys.argv[1])

if(sys.argv[1] == '-e'):
    isEncy = True

file_one = sys.argv[2]
file_two = sys.argv[3]
file_three = sys.argv[4]

if(isEncy):
    with open(file_one, 'r') as fo:
        text = fo.read()
        encrypted_aes_key = enc.encryptRSA( text)
        enc.encrypt_file(file_two, file_three, encrypted_aes_key)
else :
    with open(file_one, 'r') as fo:
        text = fo.read()
        pirvateKey = [int(x) for x in text.split("#")]
        with open(file_two, 'r') as fos:
            ciphertext = fos.read()
            cipher, enc_key = [int(x) for x in ciphertext.split(",")]
            decrypted_aes_key = enc.decryptRSA(self, pirvateKey, enc_key)
            enc.decrypt_file(cipher, file_three, decrypted_aes_key)

print("Process is done ")