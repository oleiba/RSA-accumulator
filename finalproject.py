import secrets
from helpfunctions import generateTwoLargeSafePrimes

def hashToPrime(x,lambdaCoefecient):
    #
    prime = -1
    return prime

def setup(keysize=3072):
    # draw strong primes p,q
    p,q  = generateTwoLargeSafePrimes(keysize)
    n = p*q
    # draw random number within range of [0,n-1]
    A0 = secrets.randbelow(n)
    return n, A0


def addElement(Ai,x,n,lambdaCoefecient):
    power = hashToPrime(x,lambdaCoefecient)
    result = pow(Ai,power,n)
    return result

def deleteElement(Ai, x, n):
    result = -1
    return result

def verify(A,x,proof,n):
    return pow(proof,x,n) == (A%n)
