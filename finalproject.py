import secrets
from functools import reduce

from helpfunctions import concat, generate_two_large_distinct_primes, hash_to_prime, bezoute_coefficients,\
    mul_inv

RSA_KEY_SIZE = 3072  # RSA key size for 128 bits of security (modulu size)
RSA_PRIME_SIZE = int(RSA_KEY_SIZE / 2)
ACCUMULATED_PRIME_SIZE = 128  # taken from: LLX, "Universal accumulators with efficient nonmembership proofs", construction 1


def setup():
    # draw strong primes p,q
    p, q = generate_two_large_distinct_primes(RSA_PRIME_SIZE)
    n = p*q
    # draw random number within range of [0,n-1]
    A0 = secrets.randbelow(n)
    return n, A0, dict()


def add(A, S, x, n):
    if x in S.keys():
        return A
    else:
        hash_prime, nonce = hash_to_prime(x, ACCUMULATED_PRIME_SIZE)
        A = pow(A, hash_prime, n)
        S[x] = nonce
        return A


def batch_add(A, S, xLst, n):
    product = 1
    for x in xLst:
        if x not in S.keys():
            hash_prime, nonce = hash_to_prime(x, ACCUMULATED_PRIME_SIZE)
            S[x] = nonce
            product *= hash_prime
    A = pow(A, product, n)
    return A


def prove_membership(A0, S, x, n):
    if x not in S.keys():
        return None
    else:
        product = 1
        for element in S.keys():
            if element != x:
                nonce = S[element]
                product *= hash_to_prime(element, ACCUMULATED_PRIME_SIZE, nonce)[0]
        A = pow(A0, product, n)
        return A


def prove_non_membership(A0, S, x, x_nonce, n):
    if x in S.keys():
        return None
    else:
        product = 1
        for element in S.keys():
            nonce = S[element]
            product *= hash_to_prime(element, ACCUMULATED_PRIME_SIZE, nonce)[0]
    prime = hash_to_prime(x, ACCUMULATED_PRIME_SIZE, x_nonce)[0]
    a, b = bezoute_coefficients(prime, product)
    if a < 0:
        positive_a = -a
        inverse_A0 = mul_inv(A0, n)
        d = pow(inverse_A0, positive_a, n)
    else:
        d = pow(A0, a, n)
    return d, b


def verify_non_membership(A0, A_final, d, b, x, x_nonce, n):
    prime = hash_to_prime(x, ACCUMULATED_PRIME_SIZE, x_nonce)[0]
    if b < 0:
        positive_b = -b
        inverse_A_final = mul_inv(A_final, n)
        second_power = pow(inverse_A_final, positive_b, n)
    else:
        second_power = pow(A_final, b, n)
    return (pow(d, prime, n) * second_power) % n == A0


def batch_prove_membership(A0, S, x_list, n):
    product = 1
    for element in S.keys():
        if element not in x_list:
            nonce = S[element]
            product *= hash_to_prime(element, ACCUMULATED_PRIME_SIZE, nonce)[0]
    A = pow(A0, product, n)
    return A


# AggMemWit (without Shamir trick, currently)
def batch_prove_membership_with_NIPoE(A0, S, x_list, n, w):
    u = batch_prove_membership(A0, S, x_list, n)
    primes_list = list(map(lambda x: hash_to_prime(x=x, nonce=S[x])[0], x_list))
    product = reduce(lambda first, second: first * second, primes_list, 1)
    (Q, l_nonce) = prove_exponentiation(u, product, w, n)
    return Q, l_nonce, u


def prove_membership_with_NIPoE(g, S, x, n, w):
    u = prove_membership(g, S, x, n)
    x_prime, x_nonce = hash_to_prime(x=x, nonce=S[x])
    (Q, l_nonce) = prove_exponentiation(u, x_prime, w, n)
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
    return __verify_exponentiation(Q, l_nonce, u, x, w, n)


def batch_verify_membership_with_NIPoE(Q, l_nonce, u, x_list, x_nonces_list, w, n):
    product = __calculate_primes_product(x_list, x_nonces_list)
    return __verify_exponentiation(Q, l_nonce, u, product, w, n)


# helper function, does not do hash_to_prime on x
def __verify_exponentiation(Q, l_nonce, u, x, w, n):
    l = hash_to_prime(x=(concat(x, u, w)), nonce=l_nonce)[0]
    r = x % l
    # check (Q^l)(u^r) == w
    return (pow(Q, l, n) % n) * (pow(u, r, n) % n) % n == w


def delete(A0, A, S, x, n):
    if x not in S.keys():
        return A
    else:
        del S[x]
        product = 1
        for element in S.keys():
            nonce = S[element]
            product *= hash_to_prime(element, ACCUMULATED_PRIME_SIZE, nonce)[0]
        Anew = pow(A0, product, n)
        return Anew


def batch_delete(A0, A, S, x_list, n):
    for x in x_list:
        del S[x]

    if len(S) == 0:
        return A

    product = 1
    for element in S.keys():
        nonce = S[element]
        product *= hash_to_prime(element, ACCUMULATED_PRIME_SIZE, nonce)[0]
    Anew = pow(A0, product, n)
    return Anew


def verify_membership(A, x, nonce, proof, n):
    return __verify_membership(A, hash_to_prime(x=x, num_of_bits=ACCUMULATED_PRIME_SIZE, nonce=nonce)[0], proof, n)


def batch_verify_membership(A, x_list, nonce_list, proof, n):
    product = __calculate_primes_product(x_list, nonce_list)
    return __verify_membership(A, product, proof, n)


def __calculate_primes_product(x_list, nonce_list):
    agg_list = []
    for i in range(len(x_list)):
        agg_list.append([x_list[i], nonce_list[i]])
    primes_list = map(lambda e: hash_to_prime(x=e[0], nonce=e[1])[0],  agg_list)
    product = reduce(lambda first, second: first * second, primes_list, 1)
    return product


# helper function, does not do hash to prime.
def __verify_membership(A, x, proof, n):
    return pow(proof, x, n) == A
