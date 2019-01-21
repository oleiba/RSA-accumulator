import hashlib
import secrets
import time
import matplotlib.pyplot as plt
from finalproject import setup, add_elements, prove_membership, prove_membership_with_NIPoE, batch_prove_membership, batch_prove_membership_with_NIPoE, \
    verify_membership, verify_exponentiation, batch_verify_membership, batch_verify_membership_with_NIPoE


# https://github.com/Tierion/pymerkletools
import merkletools

merkle_proof_timing = []
merkle_verify_timing = []
prove_timing = []
prove_with_NIPoE_timing = []
batch_prove_timing = []
batch_prove_with_NIPoE_timing = []
verify_timing = []
verify_with_NIPoE_timing = []
batch_verify_timing = []
batch_verify_with_NIPoE_timing = []


def create_random_set(size):
    result = []
    for index in range(0, size):
        random = secrets.randbelow(pow(2, 256))
        result.append(random)
    return result


def test_runtime(sizes ):

    n, A0, S = setup()

    for size in sizes:
        print(size)

        # first, empty the sets
        S = dict()
        set = create_random_set(size)

        # empty the Merkle Tree
        merkleTree = merkletools.MerkleTools()

        # add to the accumulator
        Anew = add_elements(A0, S, set, n)

        # add to the Merkle tree
        for i in range(len(set)):
            merkleTree.add_leaf(str(i), True)
        merkleTree.make_tree()

        # prove membership Merkle tree
        merkle_proofs = []
        tik = time.time()
        for i in range(len(set)):
            merkle_proofs.append(merkleTree.get_proof(i))
        tok = time.time()
        merkle_proof_timing.append(tok - tik)

        # basic prove membership
        # basic_proofs = []
        # tik = time.time()
        # for x in set:
        #     basic_proofs.append(prove_membership(A0, S, x, n))
        # tok = time.time()
        # prove_timing.append(tok - tik)

        # prove membership with NIPoE
        # niope_proofs = []
        # tik = time.time()
        # for x in set:
        #     niope_proofs.append(prove_membership_with_NIPoE(A0, S, x, n, Anew))
        # tok = time.time()
        # prove_with_NIPoE_timing.append(tok - tik)

        # batch prove membership
        tik = time.time()
        batch_proof = batch_prove_membership(A0, S, set, n)
        tok = time.time()
        batch_prove_timing.append(tok - tik)

        # batch prove membership with NIPoE
        tik = time.time()
        batch_proof_with_NIPoE = batch_prove_membership_with_NIPoE(A0, S, set, n, Anew)
        tok = time.time()
        batch_prove_with_NIPoE_timing.append(tok - tik)

        # Merkle tree verify membership
        merkle_root = merkleTree.get_merkle_root()
        merkle_leaves = []
        for i in range(len(set)):
            merkle_leaves.append(merkleTree.get_leaf(i))

        tik = time.time()
        for i in range(len(set)):
            b = merkleTree.validate_proof(merkle_proofs[i], merkle_leaves[i], merkle_root)
        tok = time.time()
        merkle_verify_timing.append(tok - tik)

        # basic verify membership
        # tik = time.time()
        # for proof in basic_proofs:
        #     b = verify_membership(Anew, x, S[x], proof, n)
        # tok = time.time()
        # verify_timing.append(tok - tik)

        # verify membership with NIPoE
        # tik = time.time()
        # for proof in niope_proofs:
        #     b = verify_exponentiation(proof[0], proof[1], proof[2], x, S[x], Anew, n)
        # tok = time.time()
        # verify_with_NIPoE_timing.append(tok - tik)

        # batch verify membership
        nonces_list = list(S.values())
        tik = time.time()
        batch_verify_membership(Anew, set, nonces_list, batch_proof, n)
        tok = time.time()
        batch_verify_timing.append(tok - tik)

        # batch verify membership with NIPoE
        Q, l_nonce, u = batch_proof_with_NIPoE
        tik = time.time()
        batch_verify_membership_with_NIPoE(Q, l_nonce, u, set, nonces_list, Anew, n)
        tok = time.time()
        batch_verify_with_NIPoE_timing.append(tok - tik)

sizes = []
for i in range(14):
    sizes.append(pow(2, i))
test_runtime(sizes)
fdiv1 = [float(ai)/bi for ai, bi in zip(merkle_proof_timing, sizes)]
# fdiv2 = [float(ai)/bi for ai, bi in zip(prove_timing, sizes)]
# fdiv3 = [float(ai)/bi for ai, bi in zip(prove_with_NIPoE_timing, sizes)]
fdiv4 = [float(ai)/bi for ai, bi in zip(batch_prove_timing, sizes)]
fdiv5 = [float(ai)/bi for ai, bi in zip(batch_prove_with_NIPoE_timing, sizes)]
fdiv6 = [float(ai)/bi for ai, bi in zip(merkle_verify_timing, sizes)]
# fdiv7 = [float(ai)/bi for ai, bi in zip(verify_timing, sizes)]
# fdiv8 = [float(ai)/bi for ai, bi in zip(verify_with_NIPoE_timing, sizes)]
fdiv9 = [float(ai)/bi for ai, bi in zip(batch_verify_timing, sizes)]
fdiv10 = [float(ai)/bi for ai, bi in zip(batch_verify_with_NIPoE_timing, sizes)]

print("merkle_proof_timing = ", merkle_proof_timing)
# print("prove_timing = ", prove_timing)
# print("prove_with_NIPoE_timing = ", prove_with_NIPoE_timing)
print("batch_prove_timing = ", batch_prove_timing)
print("batch_prove_with_NIPoE_timing = ", batch_prove_with_NIPoE_timing)
print("merkle_verify_timing = ", merkle_verify_timing)
# print("verify_timing = ", verify_timing)
# print("verify_with_NIPoE_timing = ", verify_with_NIPoE_timing)
print("batch_verify_timing = ", batch_verify_timing)
print("batch_verify_with_NIPoE_timing = ", batch_verify_with_NIPoE_timing)