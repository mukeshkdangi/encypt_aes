import random
import math
import sys


# Return the GCD of a and b using Euclid's Algorithm
def gcd(a, b):
    while a != 0:
        a, b = b % a, a
    return b

# Returns the modular inverse of a % m, which is
# the number x such that a*x % m = 1
# Returns the modular inverse of a % m, which is the number x such that a*x % m = 1
# no mod inverse if a & m aren't relatively prime
# // is the integer division operator

def findModInverse(a, m):
    if gcd(a, m) != 1:
        return None 
    u1, u2, u3 = 1, 0, a
    v1, v2, v3 = 0, 1, m
    while v3 != 0:
        q = u3 // v3 
        v1, v2, v3, u1, u2, u3 = (u1 - q * v1), (u2 - q * v2), (u3 - q * v3), v1, v2, v3
    return u1 % m
    
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


def rabinMiller(num):
    s = num - 1
    t = 0
    while s % 2 == 0:
        s = s // 2
        t += 1

    for trials in range(5):
        a = random.randrange(2, num - 1)
        v = pow(a, s, num)
        if v != 1:
            i = 0
            while v != (num - 1):
                if i == t - 1:
                    return False
                else:
                    i = i + 1
                    v = (v ** 2) % num
    return True

    # About 1/3 of the time we can quickly determine if num is not prime
    # by dividing by the first few dozen prime numbers. This is quicker
    # than rabinMiller(), but unlike rabinMiller() is not guaranteed to
    # prove that a number is prime.
    # See if any of the low prime numbers can divide num
    # If all else fails, call rabinMiller() to determine if num is a prime.

def isPrime(num):
    if (num < 2):
        return False
    lowPrimes = [2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61, 67, 71, 73, 79, 83, 89, 97, 101, 103, 107, 109, 113, 127, 131, 137, 139, 149, 151, 157, 163, 167, 173, 179, 181, 191, 193, 197, 199, 211, 223, 227, 229, 233, 239, 241, 251, 257, 263, 269, 271, 277, 281, 283, 293, 307, 311, 313, 317, 331, 337, 347, 349, 353, 359, 367, 373, 379, 383, 389, 397, 401, 409, 419, 421, 431, 433, 439, 443, 449, 457, 461, 463, 467, 479, 487, 491, 499, 503, 509, 521, 523, 541, 547, 557, 563, 569, 571, 577, 587, 593, 599, 601, 607, 613, 617, 619, 631, 641, 643, 647, 653, 659, 661, 673, 677, 683, 691, 701, 709, 719, 727, 733, 739, 743, 751, 757, 761, 769, 773, 787, 797, 809, 811, 821, 823, 827, 829, 839, 853, 857, 859, 863, 877, 881, 883, 887, 907, 911, 919, 929, 937, 941, 947, 953, 967, 971, 977, 983, 991, 997]

    if num in lowPrimes:
        return True

    for prime in lowPrimes:
        if (num % prime == 0):
            return False
    return rabinMiller(num)


# Return a random prime number of keysize bits in size.

def generateLargePrime(keysize=1024):
    while True:
        num = random.randrange(2**(keysize-1), 2**(keysize))
        if isPrime(num):
            return num

    # Creates a public/private key pair with keys that are keySize bits in
    # size. This function may take a while to run.
    # Step 1: Create two prime numbers, p and q. Calculate n = p * q.
    # Step 2: Create a number e that is relatively prime to (p-1)*(q-1).
    # Keep trying random numbers for e until one is valid.
    # Step 3: Calculate d, the mod inverse of e.
def generateKey(keySize):

    print('Generating p prime...')
    p = generateLargePrime(keySize)
    print('Generating q prime...')
    q = generateLargePrime(keySize)
    n = p * q

   

    print('Generating e that is relatively prime to (p-1)*(q-1)...')
    while True:
        e = random.randrange(2 ** (keySize - 1), 2 ** (keySize))
        if gcd(e, (p - 1) * (q - 1)) == 1:
             break

    print('Calculating d that is mod inverse of e...')
    d = findModInverse(e, (p - 1) * (q - 1))
    publicKey = (n, e)
    privateKey = (n, d)
    return (publicKey, privateKey)
    

if __name__ == '__main__':
    keySize =1024
    public, private = generateKey(keySize)
    print ("Your public key is ", public ," and your private key is ", private)
    with open(sys.argv[1] + ".pub", 'w') as fo:
            fo.write('%s,%s,%s' % (keySize, public[0], public[1]))
            
    with open(sys.argv[1] + ".prv", 'w') as fo:
            fo.write('%s,%s,%s' % (keySize, private[0], private[1]))


