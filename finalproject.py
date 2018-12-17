import secrets

from helpfunctions import generateTwoLargeDistinctPrimes, hashToPrime
from unittest import TestCase

KEY_SIZE = 3072  # RSA key size (2 field elements) for 128 bits of security
FE_SIZE = int(KEY_SIZE / 2)


def setup():
    print("in setup")
    # draw strong primes p,q
    p, q = generateTwoLargeDistinctPrimes(FE_SIZE)
    n = p*q
    # draw random number within range of [0,n-1]
    A0 = secrets.randbelow(n)
    return n, A0, []


def add_element(A, S, x, n):
    if x in dict(S).keys():
        return A
    else:
        prime, nonce = hashToPrime(x, FE_SIZE)
        A = pow(A, prime, n)
        S.append((x, nonce))
        return A


def prove_membership(A0, S, x, n):
    if not (x in dict(S).keys()):
        return None
    else:
        A = A0
        for s in dict(S).keys():
            if not (s == x):
                A = pow(A, hashToPrime(x, FE_SIZE)[0], n)
        return A


def delete_element(A0, A, S, x, n):
    if not (x in dict(S).keys()):
        return A
    else:
        Anew = A0
        nonce = dict(S)[x]
        S.remove((x, nonce))
        for s in S:
            Anew = pow(Anew, s, n)
        return Anew


def verify(A, x, nonce, proof, n):
    return pow(proof, hashToPrime(x=x, nonce=nonce)[0], n) == A



