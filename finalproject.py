import secrets

from helpfunctions import generateTwoLargeDistinctPrimes, hashToPrime

KEY_SIZE = 3072  # RSA key size (2 field elements) for 128 bits of security
# FE_SIZE = int(KEY_SIZE / 2)
FE_SIZE = 256


def setup():
    # draw strong primes p,q
    p, q = generateTwoLargeDistinctPrimes(int(FE_SIZE/2))
    n = p*q
    # draw random number within range of [0,n-1]
    A0 = secrets.randbelow(n)
    return n, A0, dict()


def add_element(A, S, x, n):
    if x in S.keys():
        return A
    else:
        hash_prime, nonce = hashToPrime(x, FE_SIZE)
        A = pow(A, hash_prime, n)
        S[x] = nonce
        return A


def prove_membership(A0, S, x, n):
    if x not in S.keys():
        return None
    else:
        A = A0
        for element in S.keys():
            if (element != x):
                nonce = S[element]
                A = pow(A, hashToPrime(element, FE_SIZE, nonce)[0], n)
        return A


def delete_element(A0, A, S, x, n):
    if x not in S.keys():
        return A
    else:
        Anew = A0
        del S[x]
        for element in S.keys():
            nonce = S[element]
            Anew = pow(Anew, hashToPrime(element,FE_SIZE, nonce)[0], n)
        return Anew


def verify(A, x, nonce, proof, n):
    return pow(proof, hashToPrime(x=x, num_of_bits = FE_SIZE, nonce=nonce)[0], n) == A
