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

DEFAULT_BLOCK_SIZE = 128
RSA_BYTE_SIZE = 256

class Encryptor:

    def __init__(self, key, keyToStore):
        self.key = key
        self.keyToStore = keyToStore
        self.bs = 32
        

    @staticmethod
    def dounpad(s):
        return s[:-ord(s[len(s)-1:])]
    
    def dopad(self, s):
        return s + (self.bs - len(s) % self.bs) * chr(self.bs - len(s) % self.bs)    

    def encrypt(self, raw_message):
        raw_message = self.dopad(raw_message)
        self.key = hashlib.md5(str(self.key).encode('utf-8')).digest()
        print('hashlib of key', self.key)
        cipher = AES.new(self.key, AES.MODE_ECB)
        encrypted = cipher.encrypt(raw_message)

        encoded = base64.b64encode(encrypted)
        return str(encoded, 'utf-8')   

    #use base64 to convert to string
    # Writing encrypted text @@ then encrypted_aes_key
    def encrypt_file(self, file_cip, file_txt, encrypted_aes_key):
        with open(file_txt, 'r') as fo:
            plaintext = fo.read()
        enc = self.encrypt(plaintext)
        print('writing contentn', enc)
        print('encrypted_aes_key key ', encrypted_aes_key, file_cip) 
        with open(file_cip, 'w') as fo:
            fo.write(enc+ "@@" +str(encrypted_aes_key))       

    @staticmethod    
    def decrypt(enc, key):
        # encode key and get MD5 hash 
        key = hashlib.md5(key.encode('utf-8')).digest()
        # Decode the encrypted message Base64 
        # MODE_ECB AES Cipher 
        cipher = AES.new(key, AES.MODE_ECB)
        decrypted = cipher.decrypt(base64.b64decode(enc))
        print('decrypted', decrypted)
        return str(Encryptor.dounpad(decrypted), 'utf-8')   

    @staticmethod    
    def decrypt_file(file_cip, file_txt, file_one):
        with open(file_one, 'r') as fo:
            rsa_keys = fo.read()
        #print('rsa_keys for decrypt_file', rsa_keys);
        
        with open(file_cip, 'r') as fo:
            ciphertext = fo.read()
        # Split the cipher text and store encrypted message
        ciphertext, key = ciphertext.split("@@");
        #print('ciphertext here including ency AES key ', key)    
        key = read_message_cipher_file_and_decrypt(key, file_one)

        #print('key returned after RSA decrypt', key, len(key));
        plaintext = Encryptor.decrypt(ciphertext, key)
        print('plaintext', plaintext)
        # Writing the decrypted message to the file

        with open(file_txt, 'w') as fo:
            fo.write(plaintext)


#convert list of int blocks to default_block_size string characters 
def get_blocks_from_text(message, default_block_size=DEFAULT_BLOCK_SIZE):
    message_bytes = str(message).encode('utf-8')
    block_ints = []
    for block_start in range(0, len(message_bytes), default_block_size):
        block_int = 0
        for i in range(block_start, min(block_start + default_block_size, len(message_bytes))):
            block_int += message_bytes[i] * (RSA_BYTE_SIZE ** (i % default_block_size))
        block_ints.append(block_int)
    return block_ints

# divide and decode the big message block in 128 block size
def get_text_from_blocks(block_ints, message_length, default_block_size=DEFAULT_BLOCK_SIZE):
    message = []
    for block_int in block_ints:
        block_message = []
        for i in range(default_block_size - 1, -1, -1):
            if len(message) + i < message_length:
                ascii_number = block_int // (RSA_BYTE_SIZE ** i)
                block_int = block_int % (RSA_BYTE_SIZE ** i)
                block_message.insert(0, chr(ascii_number))
        message.extend(block_message)
    return ''.join(message)

# encrypt aes key by RSA block by  block using key n, e pair 
# cipher_text = pow(plaintext, e) mod n
def encrypt_message_block_by_block(message, key, default_block_size=DEFAULT_BLOCK_SIZE):
    encrypted_blocks = []
    n, e = key
    for block in get_blocks_from_text(message, default_block_size):
        encrypted_blocks.append(pow(block, e, n))
    return encrypted_blocks

# RSA decrypts all 128 sized  blocks to original message which is our AES key 
# Of Specifies length divide in 128 sized blocks 
# plain_text = pow(ciphertext, d) mod n
def decrypt_message_block_by_block(encrypted_blocks, message_length, key, default_block_size=DEFAULT_BLOCK_SIZE):
    decrypted_blocks = []
    n, d = key
    for block in encrypted_blocks:
        decrypted_blocks.append(pow(block, d, n))
    return get_text_from_blocks(decrypted_blocks, message_length, default_block_size)


def read_alice_bob_key_file(key_file_name):
    # Given the filename of a file that contains a public or private key,
    # return the key as a (n,e) or (n,d) tuple value.
    fo = open(key_file_name)
    file_content = fo.read()
    #Close file 
    fo.close()
    keySize, n, E_or_D = file_content.split(',')
    return (int(keySize), int(n), int(E_or_D))


def encrypt_message_txt_file_and_Write_to_cipher_file(key_file_name, message, default_block_size=DEFAULT_BLOCK_SIZE):
    # Using a key from a key file, encrypt the message and save it to a
    # file. Returns the encrypted message string.
    key_size, n, e = read_alice_bob_key_file(key_file_name)

    # Check that key size is greater than block size.
    if key_size < default_block_size * 8: # * 8 to convert bytes to bits
        sys.exit('ERROR: Block size is %s bits and key size is %s bits. The RSA cipher requires the block size to be equal to or greater than the key size. Either decrease the block size or use different keys.' % (blockSize * 8, keySize))


    # Encrypt the message
    encrypted_blocks = encrypt_message_block_by_block(message, (n, e), default_block_size)
   
    for i in range(len(encrypted_blocks)):
        encrypted_blocks[i] = str(encrypted_blocks[i])
    encrypted_content = ','.join(encrypted_blocks)
    encrypted_content = '%s_%s_%s' % (len(str(message)), default_block_size, encrypted_content)
    return encrypted_content


def read_message_cipher_file_and_decrypt(content, key_file_name):
    # Using a key from a key file, read an encrypted message from a file
    # and then decrypt it. Returns the decrypted message string.
    key_size, n, d = read_alice_bob_key_file(key_file_name)
    #print('keySize, n, d', keySize, n, d)
    print('content', content)

    message_length, block_size, encrypted_message = content.split('_')
    message_length = int(message_length)
    block_size = int(block_size)

    # Check that key size is greater than block size.
    if key_size < block_size * 8: # * 8 to convert bytes to bits
        sys.exit('ERROR: Block size is %s bits and key size is %s bits. The RSA cipher requires the block size to be equal to or greater than the key size. Did you specify the correct key file and encrypted file?' % (blockSize * 8, keySize))

    # Convert the encrypted message into large int values.
    encrypted_blocks = []
    for block in encrypted_message.split(','):
        encrypted_blocks.append(int(block))

    # Decrypt the large int values.
    return decrypt_message_block_by_block(encrypted_blocks, message_length, (n, d), block_size)           


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
    #print('keyK1 $$$$$$$$$$$$$$$$$$$$$$$$$ keyK1', keyK1)
    #init key to Encryptor class 
    enc = Encryptor(keyK1, keyK)

    encrypted_aes_key = encrypt_message_txt_file_and_Write_to_cipher_file(file_one, keyK)
    enc.encrypt_file(file_three, file_two, encrypted_aes_key)
        
#./crypt.py -d bob.prv message.cip message.txt        
else :
    Encryptor.decrypt_file(file_two, file_three, file_one)
        

print("Process is done ")