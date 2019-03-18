import random
import math
import sys

def gcd(a, b):
    while b != 0:
        a, b = b, a % b
    return a

def egcd(a, b):
    if a == 0:
        return b, 0, 1
    else:
        g, y, x = egcd(b % a, a)
        return g, x - (b // a) * y, y

def multiplicative_inverse(a, m):
    g, x, y = egcd(a, m)
    if g != 1:
        raise Exception('modular inverse does not exist')
    else:
        return x % m
    
def get_primes(start, stop):
    if start >= stop:
        return []
    primes = [2]
    for n in range(3, stop + 1, 2):
        for p in primes:
            if n % p == 0:
                break
        else:
            primes.append(n)

    while primes and primes[0] < start:
        del primes[0]

    return primes

def are_relatively_prime(a, b):
    for n in range(2, min(a, b) + 1):
        if a % n == b % n == 0:
            return False
    return True

def is_prime(n):
    if n % 2 == 0 and n > 2: 
        return False
    return all(n % i for i in range(3, int(math.sqrt(n)) + 1, 2))

def generate_keypair(length):
    n_min = 1 << (length - 1)
    n_max = (1 << length) - 1
    start = 1 << (length // 2 - 1)
    stop = 1 << (length // 2 + 1)
    primes = get_primes(start, stop)
    while primes:
        p = random.choice(primes)
        primes.remove(p)
        q_candidates = [q for q in primes
                        if n_min <= p * q <= n_max]
        if q_candidates:
            q = random.choice(q_candidates)
            break
    else:
        raise AssertionError("cannot find 'p' and 'q' for a key of "
                             "length={!r}".format(length))

    print('p', p , 'q' , q)    
    n = p * q
    phi = (p-1) * (q-1)
   #Choose an integer e such that e and phi(n) are coprime
    e = random.randrange(1, phi)

    #Use Euclid's Algorithm to verify that e and phi(n) are comprime
    g = gcd(e, phi)
    while g != 1:
        e = random.randrange(1, phi)
        g = gcd(e, phi)

    #Use Extended Euclid's Algorithm to generate the private key
    d = multiplicative_inverse(e, phi)
    return ((e, n), (d, n))

def encryptRSA(pk, plaintext):
    key, n = pk
    #Convert each letter in the plaintext to numbers based on the character using a^b mod m
    cipher = [math.pow(ord(char), key) % n for char in plaintext]
    #Return the array of bytes
    return cipher

def decryptRSA(pk, ciphertext):
    #Unpack the key into its components
    key, n = pk
    #Generate the plaintext based on the ciphertext and key using a^b mod m
    plain = [math.pow(chr(char), key) % n for char in ciphertext]
    #Return the array of bytes as a string
    return ''.join(plain)
    

if __name__ == '__main__':

    public, private = generate_keypair(25)
    
    print ("Your public key is ", public ," and your private key is ", private)
    e, n = public
    d, n = private
    with open(sys.argv[1] + ".pub", 'w') as fo:
            fo.write(str(e)+'#'+str(n))
            
    with open(sys.argv[1] + ".prv", 'w') as fo:
            fo.write(str(d)+'#'+str(n))        
            
    #encrypted_msg = encrypt(private, message)
    #print ("Your encrypted message is: ")
    #print (''.join(map(lambda x: str(x), encrypted_msg)))
    #print ("Decrypting message with public key ", public ," . . .")
    #print ("Your message is:")
    #print (decrypt(public, encrypted_msg))