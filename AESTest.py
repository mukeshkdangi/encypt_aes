from Crypto import Random
from Crypto.Cipher import AES
import os
import os.path
from os import listdir
from os.path import isfile, join
import time
import sys
import random
import base64



class Encryptor:

    def __init__(self, key, keyToStore):
        self.key = key
        self.keyToStore = keyToStore
        self.bs = 32

    def _pad(self, s):
        return s + (self.bs - len(s) % self.bs) * chr(self.bs - len(s) % self.bs)    

    def encrypt(self, raw):
        raw = self._pad(raw)
        
        iv = Random.new().read(AES.block_size)
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        return base64.b64encode(iv + cipher.encrypt(raw)).decode('ascii')    

    def encrypt_file(self, file_txt, file_cip, encrypted_aes_key):
        with open(file_txt, 'r') as fo:
            plaintext = fo.read()

        enc = self.encrypt(plaintext)
        print('writing contentn', enc)
        print('encrypted_aes_key key ', encrypted_aes_key)
        #use base64 to convert to string 
        with open(file_cip, 'w') as fo:
            fo.write(enc+"@@"+str(encrypted_aes_key))       

    @staticmethod
    def _unpad(s):
        return s[:-ord(s[len(s)-1:])]
    
    @staticmethod    
    def decrypt(enc, key):
        print('trying to descript ', enc );
        enc = base64.b64decode(enc)
        iv = enc[:AES.block_size]
        key = key.to_bytes(32, "big")
        print('trying to descript ', enc );

        print('\n key is ', key);
        cipher = AES.new(key, AES.MODE_CBC, iv)
        return cipher.decrypt(enc[AES.block_size:])

    @staticmethod    
    def decrypt_file(file_cip, file_txt, rsa_keys):
        
        with open(file_cip, 'r') as fo:
            ciphertext = fo.read()
  
        ciphertext, key = ciphertext.split("@@");
        key = Encryptor.decryptRSA(rsa_keys, key);
        print('key returned after RSA decrypt', key);

        plaintext = Encryptor.decrypt(ciphertext, key)
        print('plaintext', plaintext)
        with open(file_txt, 'w') as fo:
            fo.write(plaintext.decode('ascii'))


    def encryptRSA(self, file_text):
        key, n = file_text.split("#")
        plaintext = self.keyToStore
        print('AES Key Before ', self.keyToStore)
        cipher=pow(int(plaintext), int(key), int(n))
        print('AES Key After RSA Enc' , cipher)
        return cipher

    @staticmethod
    def decryptRSA(pk, ciphertext):
        print('decryptRSA pk', pk)
        key, n = pk.split("#")
        print('ciphertext for decryptRSA',ciphertext)
        plain = pow(int(ciphertext), int(key), int(n))
        print('AES Decrypted key ' , plain)
        return plain        


clear = lambda: os.system('cls')
print('First arg is ', sys.argv[1])
isEncy = False

if(sys.argv[1] == '-e'):
    isEncy = True

file_one = sys.argv[2]
file_two = sys.argv[3]
file_three = sys.argv[4]
#/crypt.py -e bob.pub message.txt message.cip
if(isEncy):
    keyK = random.getrandbits(128)
    keyK1= keyK.to_bytes(32, "big")
    enc = Encryptor(keyK1, keyK)
    with open(file_one, 'r') as fo:
        text = fo.read()
        encrypted_aes_key = enc.encryptRSA(text)
        enc.encrypt_file(file_three, file_two, encrypted_aes_key)
        
#./crypt.py -d bob.prv message.cip message.txt        
else :
    with open(file_one, 'r') as fo:
        rsa_keys = fo.read()
        Encryptor.decrypt_file(file_two, file_three, rsa_keys)
        

print("Process is done ")