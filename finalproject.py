import secrets

from helpfunctions import generate_two_large_distinct_primes, hash_to_prime

KEY_SIZE = 3072  # RSA key size (2 field elements) for 128 bits of security
GE_SIZE = int(KEY_SIZE / 2)  # RSA group element size in bits
ACCUMULATED_PRIME_SIZE = 128  # taken from: LLX, "Universal accumulators with efficient nonmembership proofs", construction 1


def setup():
    # draw strong primes p,q
    p, q = generate_two_large_distinct_primes(GE_SIZE)
    n = p*q
    # draw random number within range of [0,n-1]
    A0 = secrets.randbelow(n)
    return n, A0, dict()


def add_element(A, S, x, n):
    if x in S.keys():
        return A
    else:
        hash_prime, nonce = hash_to_prime(x, ACCUMULATED_PRIME_SIZE)
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
                A = pow(A, hash_to_prime(element, ACCUMULATED_PRIME_SIZE, nonce)[0], n)
        return A


def delete_element(A0, A, S, x, n):
    if x not in S.keys():
        return A
    else:
        Anew = A0
        del S[x]
        for element in S.keys():
            nonce = S[element]
            Anew = pow(Anew, hash_to_prime(element, ACCUMULATED_PRIME_SIZE, nonce)[0], n)
        return Anew


def verify(A, x, nonce, proof, n):
    return pow(proof, hash_to_prime(x=x, num_of_bits=ACCUMULATED_PRIME_SIZE, nonce=nonce)[0], n) == A
