import secrets

from helpfunctions import concat, generate_two_large_distinct_primes, hash_to_prime, mul_inv

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
            if element != x:
                nonce = S[element]
                A = pow(A, hash_to_prime(element, ACCUMULATED_PRIME_SIZE, nonce)[0], n)
        return A


def prove_membership_with_PoE(g, S, x, n, w):
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
#   Q, x - the PoE
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
    return pow(proof, hash_to_prime(x=x, num_of_bits=ACCUMULATED_PRIME_SIZE, nonce=nonce)[0], n) == A
