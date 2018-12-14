import secrets
import hashlib
from helpfunctions import generateTwoLargeSafePrimes, hashToPrime

KEY_SIZE = 3072  # RSA key size (2 field elements) for 128 bits of security 

def setup():
    # draw strong primes p,q
    p,q  = generateTwoLargeSafePrimes(int(KEY_SIZE / 2))
    n = p*q
    # draw random number within range of [0,n-1]
    A0 = secrets.randbelow(n)
    return n, A0

def addElement(Ai,x,n,):
    power = hashToPrime(x, int(KEY_SIZE / 2))
    result = pow(Ai,power,n)
    return result

def deleteElement(Ai, x, n):
    result = -1
    return result

def verify(A,x,proof,n):
    return pow(proof,x,n) == (A%n)
