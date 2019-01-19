import time
import secrets

from finalproject import setup, add_element, prove_membership, delete_element, verify

def create_set(size):
    set = []
    for i in range(size):
        set.append(secrets.randbelow(pow(2, 128)))
    return set

set = create_set(1000)
n, A, S = setup()

time_adds = 0
start = time.time()
for i in range(1000):
    A = add_element(A, S, set[i], n)
end = time.time()
time_adds = end - start

print("total =", time_adds)
