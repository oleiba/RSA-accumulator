import secrets
from functools import reduce

from helpfunctions import concat, generate_two_large_distinct_primes, hash_to_prime

RSA_KEY_SIZE = 2048  # RSA key size for 128 bits of security (modulu size)
RSA_PRIME_SIZE = int(RSA_KEY_SIZE / 2)
ACCUMULATED_PRIME_SIZE = 128  # taken from: LLX, "Universal accumulators with efficient nonmembership proofs", construction 1


def setup():
    # draw strong primes p,q
    p, q = generate_two_large_distinct_primes(RSA_PRIME_SIZE)
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

def add_elements(A, S, xLst, n):
    aggHashToPrime = 1
    for x in xLst:
        if x not in S.keys():
            hash_prime, nonce = hash_to_prime(x, ACCUMULATED_PRIME_SIZE)
            S[x] = nonce
            aggHashToPrime*=hash_prime
    A = pow(A, aggHashToPrime, n)
    return A

def prove_membership(A0, S, x, n):
    if x not in S.keys():
        return None
    else:
        A = A0
        for element in S.keys():
            if element != x:
                nonce = S[element]
                A = pow(A, hash_to_prime(element, ACCUMULATED_PRIME_SIZE, nonce)[0], n)
        return A


def batch_prove_membership(A0, S, x_list, n):
    A = A0
    for element in S.keys():
        if element not in x_list:
            nonce = S[element]
            A = pow(A, hash_to_prime(element, ACCUMULATED_PRIME_SIZE, nonce)[0], n)
    return A


def prove_membership_with_NIPoE(g, S, x, n, w):
    u = prove_membership(g, S, x, n)
    x_prime, x_nonce = hash_to_prime(x=x, nonce=S[x])
    (Q, l_nonce) = prove_exponentiation(u, x_prime, w, n)
    return Q, l_nonce, u


def batch_prove_membership_with_NIPoE(A0, S, x_list, n, w):
    u = batch_prove_membership(A0, S, x_list, n)
    primes_list = list(map(lambda x: hash_to_prime(x)[0], x_list))
    # primes_list = list(map(lambda e: e[0], primes_nonces_list))
    # nonces_list = list(map(lambda e: e[1], primes_nonces_list))
    product = reduce(lambda first, second: first * second, primes_list, 1)
    (Q, l_nonce) = prove_exponentiation(u, product, w, n)
    return Q, l_nonce, u


# NI-PoE: non-interactive version of section 3.1 in BBF18 (PoE).
# Receives:
#   u - the accumulator value before add
#   x - the (prime) element which was added to the accumulator
#   w - the accumulator after the addition of x
#   n - the modulu
# Returns:
#   Q, x - the NIPoE
#   nonce - the nonce used for hash_to_prime to receive l (for saving work to the verifier)
def prove_exponentiation(u, x, w, n):
    l, nonce = hash_to_prime(concat(x, u, w))  # Fiat-Shamir instead of interactive challenge
    q = x // l
    Q = pow(u, q, n)
    return Q, nonce


# Verify NI-PoE
# we pass the l_nonce just for speed up. The verifier has to reproduce l himself.
def verify_exponentiation(Q, l_nonce, u, x, x_nonce, w, n):
    x = hash_to_prime(x=x, nonce=x_nonce)[0]
    return _verify_exponentiation(Q, l_nonce, u, x, w, n)


def batch_verify_membership_with_NIPoE(Q, l_nonce, u, x_list, x_nonces_list, w, n):
    product = _calculate_primes_product(x_list, x_nonces_list)
    return _verify_exponentiation(Q, l_nonce, u, product, w, n)


# helper function, does not do hash_to_prime on x
def _verify_exponentiation(Q, l_nonce, u, x, w, n):
    l = hash_to_prime(x=(concat(x, u, w)), nonce=l_nonce)[0]
    r = x % l
    # check (Q^l)(u^r) == w
    return pow(Q, l, n) * pow(u, r, n) % n == w


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
    return _verify(A, hash_to_prime(x=x, num_of_bits=ACCUMULATED_PRIME_SIZE, nonce=nonce)[0], proof, n)


def batch_verify_membership(A, x_list, nonce_list, proof, n):
    product = _calculate_primes_product(x_list, nonce_list)
    return _verify(A, product, proof, n)


def _calculate_primes_product(x_list, nonce_list):
    agg_list = []
    for i in range(len(x_list)):
        agg_list.append([x_list[i], nonce_list[i]])
    primes_list = map(lambda e: hash_to_prime(x=e[0], nonce=e[1])[0],  agg_list)
    product = reduce(lambda first, second: first * second, primes_list, 1)
    return product


# helper function, does not do hash to prime.
def _verify(A, x, proof, n):
    return pow(proof, x, n) == A
