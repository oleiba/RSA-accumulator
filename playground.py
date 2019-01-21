import time
import secrets

from helpfunctions import hash_to_prime
from finalproject import setup, add, prove_membership, delete, verify_membership, prove_membership_with_PoE, verify_exponentiation


def create_set(size):
    set = []
    for i in range(size):
        x = secrets.randbelow(pow(2, 256))
        set.append(x)
    return set


set = create_set(100)
n, A_0, S = setup()

time_adds = 0
start = time.time()
A_N = A_0
for i in range(len(set)):
    A_N = add(A_N, S, set[i], n)
end = time.time()
total_time = end - start
print("Total time add =", total_time)
print("Add average:=", total_time / len(set))

set_of_proofs_1 =  []
start = time.time()
for i in range(len(set)):
    set_of_proofs_1.append(prove_membership(A_0, S, set[i], n))
end = time.time()
total_time = end - start
print("Total time prove =", total_time)
print("Prove average =", total_time / len(set))

set_of_proofs_2 = []
start = time.time()
for i in range(len(set)):
    set_of_proofs_2.append(prove_membership_with_PoE(A_0, S, set[i], n, A_N))
end = time.time()
total_time = end - start
print("Total time prove with PoE =", total_time)
print("Prove average =", total_time / len(set))


start = time.time()
for i in range(len(set)):
    if not verify_membership(A_N, set[i], S[set[i]], set_of_proofs_1[i], n):
        print("ERROR")
end = time.time()
total_time = end - start
print("Total time basic verify membership =", total_time)
print("Basic verify membership average=", total_time / len(set))

start = time.time()
for i in range(len(set)):
    if not verify_exponentiation(set_of_proofs_2[i][0], set_of_proofs_2[i][1], set_of_proofs_2[i][2], set[i], S[set[i]], A_N, n):
        print("ERROR")
end = time.time()
total_time = end - start
print("Total time basic verify membership =", total_time)
print("PoE verify average=", total_time / len(set))

print("-------------")

