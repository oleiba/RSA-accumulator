import secrets

from helpfunctions import concat, generate_two_large_distinct_primes, hash_to_prime, bezoute_coefficients,\
    mul_inv, shamir_trick, calculate_product

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


def batch_add(A_pre_add, S, x_list, n):
    product = 1
    for x in x_list:
        if x not in S.keys():
            hash_prime, nonce = hash_to_prime(x, ACCUMULATED_PRIME_SIZE)
            S[x] = nonce
            product *= hash_prime
    A_post_add = pow(A_pre_add, product, n)
    return A_post_add, prove_exponentiation(A_pre_add, product, A_post_add, n)


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


def batch_prove_membership_with_NIPoE(A0, S, x_list, n, w):
    u = batch_prove_membership(A0, S, x_list, n)
    nonces_list = []
    for x in x_list:
        nonces_list.append(S[x])
    product = __calculate_primes_product(x_list, nonces_list)
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


def batch_delete(A0, S, x_list, n):
    for x in x_list:
        del S[x]

    if len(S) == 0:
        return A0

    return batch_add(A0, S, x_list, n)


# agg_indexes: in case proofs_list actually relate to some aggregation of the inputs in x_list, it should contain pairs
# of start index and end index.
def batch_delete_using_membership_proofs(A_pre_delete, S, x_list, proofs_list, n, agg_indexes=[]):
    is_aggregated = len(agg_indexes) > 0
    if is_aggregated and len(proofs_list) != len(agg_indexes):
        return None

    if (not is_aggregated) and len(x_list) != len(proofs_list):
        return None

    members = []
    if is_aggregated:
        # sanity - verify each and every proof individually
        for i, indexes in enumerate(agg_indexes):
            current_x_list = x_list[indexes[0]: indexes[1]]
            current_nonce_list = [S[x] for x in current_x_list]
            product = __calculate_primes_product(current_x_list, current_nonce_list)
            members.append(product)
            for x in current_x_list:
                del S[x]
    else:
        for x in x_list:
            members.append(hash_to_prime(x, ACCUMULATED_PRIME_SIZE, S[x])[0])
            del S[x]

    A_post_delete = proofs_list[0]
    product = members[0]

    for i in range(len(members))[1:]:
        A_post_delete = shamir_trick(A_post_delete, proofs_list[i], product, members[i], n)
        product *= members[i]

    return A_post_delete, prove_exponentiation(A_post_delete, product, A_pre_delete, n)


def verify_membership(A, x, nonce, proof, n):
    return __verify_membership(A, hash_to_prime(x=x, num_of_bits=ACCUMULATED_PRIME_SIZE, nonce=nonce)[0], proof, n)


def batch_verify_membership(A, x_list, nonce_list, proof, n):
    product = __calculate_primes_product(x_list, nonce_list)
    return __verify_membership(A, product, proof, n)


def __calculate_primes_product(x_list, nonce_list):
    if len(x_list) != len(nonce_list):
        return None

    primes_list = [hash_to_prime(x, nonce=nonce_list[i])[0] for i, x in enumerate(x_list)]
    product = calculate_product(primes_list)
    return product


# helper function, does not do hash to prime.
def __verify_membership(A, x, proof, n):
    return pow(proof, x, n) == A
