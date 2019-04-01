from Crypto import Random
from Crypto.Cipher import AES
import os
import os.path
from os import listdir
from os.path import isfile, join
import time
import sys
import random
import base64, re
from Crypto.Random import get_random_bytes
import hashlib

DEFAULT_BLOCK_SIZE = 128 # 128 bytes
BYTE_SIZE = 256 # One byte has 256 different values.

class Encryptor:

    def __init__(self, key, keyToStore):
        self.key = key
        self.keyToStore = keyToStore
        self.bs = 32
        

    @staticmethod
    def unpad(s):
        return s[:-ord(s[len(s)-1:])]
    
    def pad(self, s):
        return s + (self.bs - len(s) % self.bs) * chr(self.bs - len(s) % self.bs)    

    def encrypt(self, raw):
        raw = self.pad(raw)
        #self.key = hashlib.sha256(key.encode()).digest()
        self.key = hashlib.md5(self.key.encode()).digest()
        print('Hex of key', self.key)
        cipher = AES.new(self.key, AES.MODE_ECB)
        encrypted = cipher.encrypt(raw)
        encoded = base64.b64encode(encrypted)
        return str(encoded, 'utf-8')   

    def encrypt_file(self, file_cip, file_txt, encrypted_aes_key):
        with open(file_txt, 'r') as fo:
            plaintext = fo.read()

        enc = self.encrypt(plaintext)
        print('writing contentn', enc)
        print('encrypted_aes_key key ', encrypted_aes_key, file_cip)
        #use base64 to convert to string 
        with open(file_cip, 'w') as fo:
            fo.write(enc+ "@@" +str(encrypted_aes_key))       

    @staticmethod    
    def decrypt(enc, key):
        print('trying to descript ', enc );
        print('\n key is ', key)
        #key = (key).decode('utf-8')
        key = hashlib.md5(key.encode('utf-8')).digest()
        print('Hex of key', key)
        decoded = base64.b64decode(enc)
        cipher = AES.new(key, AES.MODE_ECB)
        decrypted = cipher.decrypt(decoded)
        print('decrypted', decrypted)
        return str(Encryptor.unpad(decrypted), 'utf-8')   

    @staticmethod    
    def decrypt_file(file_cip, file_txt, file_one):
        with open(file_one, 'r') as fo:
            rsa_keys = fo.read()
            print('rsa_keys for decrypt_file', rsa_keys);
        
        with open(file_cip, 'r') as fo:
            ciphertext = fo.read()
        
        ciphertext, key = ciphertext.split("@@");
        print('ciphertext here including ency AES key ', key)    
        key = readFromFileAndDecrypt(key, file_one)

        print('key returned after RSA decrypt', key, len(key));
        plaintext = Encryptor.decrypt(ciphertext, key)
        print('plaintext', plaintext)
        with open(file_txt, 'w') as fo:
            fo.write(plaintext)



def getBlocksFromText(message, blockSize=DEFAULT_BLOCK_SIZE):
    # Converts a string message to a list of block integers. Each integer
    # represents 128 (or whatever blockSize is set to) string characters.

    messageBytes = str(message).encode('utf-8') # convert the string to bytes

    blockInts = []
    for blockStart in range(0, len(messageBytes), blockSize):
        # Calculate the block integer for this block of text
        blockInt = 0
        for i in range(blockStart, min(blockStart + blockSize, len(messageBytes))):
            blockInt += messageBytes[i] * (BYTE_SIZE ** (i % blockSize))
        blockInts.append(blockInt)
    return blockInts


def getTextFromBlocks(blockInts, messageLength, blockSize=DEFAULT_BLOCK_SIZE):
    # Converts a list of block integers to the original message string.
    # The original message length is needed to properly convert the last
    # block integer.
    message = []
    for blockInt in blockInts:
        blockMessage = []
        for i in range(blockSize - 1, -1, -1):
            if len(message) + i < messageLength:
                # Decode the message string for the 128 (or whatever
                # blockSize is set to) characters from this block integer.
                asciiNumber = blockInt // (BYTE_SIZE ** i)
                blockInt = blockInt % (BYTE_SIZE ** i)
                blockMessage.insert(0, chr(asciiNumber))
        message.extend(blockMessage)
    return ''.join(message)


def encryptMessage(message, key, blockSize=DEFAULT_BLOCK_SIZE):
    # Converts the message string into a list of block integers, and then
    # encrypts each block integer. Pass the PUBLIC key to encrypt.
    encryptedBlocks = []
    n, e = key

    for block in getBlocksFromText(message, blockSize):
        # ciphertext = plaintext ^ e mod n
        encryptedBlocks.append(pow(block, e, n))
    return encryptedBlocks


def decryptMessage(encryptedBlocks, messageLength, key, blockSize=DEFAULT_BLOCK_SIZE):
    # Decrypts a list of encrypted block ints into the original message
    # string. The original message length is required to properly decrypt
    # the last block. Be sure to pass the PRIVATE key to decrypt.
    decryptedBlocks = []
    n, d = key
    for block in encryptedBlocks:
        print('processing block', block)

        # plaintext = ciphertext ^ d mod n
        decryptedBlocks.append(pow(block, d, n))
    return getTextFromBlocks(decryptedBlocks, messageLength, blockSize)


def readKeyFile(keyFilename):
    # Given the filename of a file that contains a public or private key,
    # return the key as a (n,e) or (n,d) tuple value.
    fo = open(keyFilename)
    content = fo.read()
    fo.close()
    keySize, n, EorD = content.split(',')
    return (int(keySize), int(n), int(EorD))


def encryptAndWriteToFile(keyFilename, message, blockSize=DEFAULT_BLOCK_SIZE):
    # Using a key from a key file, encrypt the message and save it to a
    # file. Returns the encrypted message string.
    keySize, n, e = readKeyFile(keyFilename)

    # Check that key size is greater than block size.
    if keySize < blockSize * 8: # * 8 to convert bytes to bits
        sys.exit('ERROR: Block size is %s bits and key size is %s bits. The RSA cipher requires the block size to be equal to or greater than the key size. Either decrease the block size or use different keys.' % (blockSize * 8, keySize))


    # Encrypt the message
    encryptedBlocks = encryptMessage(message, (n, e), blockSize)
   
    for i in range(len(encryptedBlocks)):
        encryptedBlocks[i] = str(encryptedBlocks[i])
    encryptedContent = ','.join(encryptedBlocks)
    encryptedContent = '%s_%s_%s' % (len(str(message)), blockSize, encryptedContent)
    return encryptedContent


def readFromFileAndDecrypt(content, keyFilename):
    # Using a key from a key file, read an encrypted message from a file
    # and then decrypt it. Returns the decrypted message string.
    keySize, n, d = readKeyFile(keyFilename)
    print('keySize, n, d', keySize, n, d)
    print('content', content)

    messageLength, blockSize, encryptedMessage = content.split('_')
    messageLength = int(messageLength)
    blockSize = int(blockSize)

    # Check that key size is greater than block size.
    if keySize < blockSize * 8: # * 8 to convert bytes to bits
        sys.exit('ERROR: Block size is %s bits and key size is %s bits. The RSA cipher requires the block size to be equal to or greater than the key size. Did you specify the correct key file and encrypted file?' % (blockSize * 8, keySize))

    # Convert the encrypted message into large int values.
    encryptedBlocks = []
    for block in encryptedMessage.split(','):
        encryptedBlocks.append(int(block))

    # Decrypt the large int values.
    return decryptMessage(encryptedBlocks, messageLength, (n, d), blockSize)           


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
    keyK1 = keyK
    print('keyK1 $$$$$$$$$$$$$$$$$$$$$$$$$ keyK1', keyK1)
    enc = Encryptor(keyK1, keyK)

    encrypted_aes_key = encryptAndWriteToFile(file_one, keyK)
    enc.encrypt_file(file_three, file_two, encrypted_aes_key)
        
#./crypt.py -d bob.prv message.cip message.txt        
else :
    Encryptor.decrypt_file(file_two, file_three, file_one)
        

print("Process is done ")