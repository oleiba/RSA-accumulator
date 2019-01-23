# This file is used to generate a proof for the RSAAccumulator smart contract
import sys
import secrets
from main import setup, add, prove_membership
from helpfunctions import hash_to_prime


def to_padded_num_str(num, length_in_bytes):
    length_in_hex_str = length_in_bytes * 2 + 2
    num_str = format(num, '#0' + str(length_in_hex_str) + 'x')
    return num_str


n, A0, S = setup()


x = secrets.randbelow(pow(2, 256))
A1 = add(A0, S, x, n)
nonce = S[x]
proof = prove_membership(A0, S, x, n)
prime, nonce = hash_to_prime(x=x, nonce=nonce)

print(to_padded_num_str(n, 384) + ',' + to_padded_num_str(proof, 384) + ',' + to_padded_num_str(prime, 32) + ',' + to_padded_num_str(A1, 384))
sys.stdout.flush()
