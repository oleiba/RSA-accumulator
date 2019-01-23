import time
from main import setup, batch_add, batch_prove_membership, batch_prove_membership_with_NIPoE, \
    batch_verify_membership, batch_verify_membership_with_NIPoE, batch_delete_using_membership_proofs
from helpfunctions import hash_to_prime, calculate_product
import csv
import os
import random

# https://github.com/Tierion/pymerkletools
import merkletools

# add (for all new utxos in block)
merkle_add_timing = []
acc_batch_add_genesis_timing = []
acc_batch_add_per_block_timing = []

# delete (for all spent txos in block)
acc_delete_timing = []
acc_batch_delete_timing = []

# prove membership
merkle_proof_timing = []
acc_prove_mem_timing = []
acc_prove_mem_with_NIPoE_timing = []
acc_batch_prove_mem_timing = []
acc_batch_prove_mem_with_NIPoE_timing = []

# verify membership ; per tx
merkle_verify_mem_per_tx_timing = []
acc_verify_mem_per_tx_timing = []
acc_verify_mem_with_NIPoE_per_tx_timing = []
acc_batch_verify_mem_per_tx_timing = []
acc_batch_verify_mem_with_NIPoE_per_tx_timing = []

# verify membership per block
merkle_verify_mem_per_block_timing = []
acc_verify_mem_per_block_timing = []
acc_verify_mem_with_NIPoE_per_block_timing = []
acc_batch_verify_mem_per_block_timing = []
acc_batch_verify_mem_with_NIPoE_per_block_timing = []

# verify aggregated 2 NI-PoE inclusion proofs after block mining
acc_batch_verify_two_NIPoE_post_mining = []


GENERATED_CSV_DIRECTORY = 'generated'


def create_random_list(size):
    result = []
    for index in range(0, size):
        random_element = random.randint(1, pow(2, 256))
        result.append(random_element)
    return result


# Test the performance during block mining process:
# 1. filling up the sets
# 2. a client generates an aggregated proof for all the utxos in his tx (we assume a stateful client for accumulator, so we have something to measure)
# 3. a miner batch-verifies-membership for the aggregated proof for the transaction
# 4. a miner batch-deletes + generates deletion NI-PoE all the spent utxos in block
# 5. a miner batch-adds + generates second NI-PoE for all the new utxos in block
# 6. all nodes batch-verify both proofs from steps 4,5
def test_mining(total_utxo_set_size_for_merkle_tree, total_utxo_set_size_for_accumulator, num_of_inputs_in_tx, num_of_outputs_in_tx, num_of_txs_in_block):
    print("----------------------")
    print("total_utxo_set_size_for_merkle_tree =", total_utxo_set_size_for_merkle_tree)
    print("total_utxo_set_size_for_accumulator =", total_utxo_set_size_for_accumulator)
    print("num_of_inputs_in_tx =", num_of_inputs_in_tx)
    print("num_of_outputs_in_tx =", num_of_outputs_in_tx)
    print("num_of_txs_in_block =", num_of_txs_in_block)

    print("--> initialize and fill up Merkle tree state")
    merkle_tree = merkletools.MerkleTools()
    elements_for_merkle_tree = create_random_list(total_utxo_set_size_for_merkle_tree)
    tik = time.time()
    for i in range(len(elements_for_merkle_tree)):
        merkle_tree.add_leaf(str(i), True)
    merkle_tree.make_tree()
    tok = time.time()
    merkle_add_timing.append(tok - tik)
    print("<--   Done.", merkle_add_timing[-1])

    print("--> initialize and fill up accumulator state")
    n, A0, S = setup()
    if total_utxo_set_size_for_accumulator < num_of_inputs_in_tx * num_of_txs_in_block:
        print("please select larger total_utxo_set_size_for_accumulator.")
        return None
    elements_for_accumulator = create_random_list(total_utxo_set_size_for_accumulator)
    inputs_for_accumulator = elements_for_accumulator[0:(num_of_inputs_in_tx * num_of_txs_in_block)]
    outputs_for_accumulator = create_random_list(num_of_outputs_in_tx * num_of_txs_in_block)
    tik = time.time()
    A_post_batch_add, proof = batch_add(A0, S, elements_for_accumulator, n)
    inputs_nonces_list = [S[x] for x in inputs_for_accumulator]
    tok = time.time()
    acc_batch_add_genesis_timing.append(tok - tik)
    print("<--   Done.", acc_batch_add_genesis_timing[-1])

    print("--> prove membership Merkle tree")
    times = []
    merkle_proofs = []
    for i in range(num_of_inputs_in_tx * num_of_txs_in_block):
        tik = time.time()
        merkle_proofs.append(merkle_tree.get_proof(i))
        tok = time.time()
        times.append(tok - tik)
    sum_times = sum(times)
    merkle_proof_timing.append(sum_times / num_of_inputs_in_tx)  # average ; per tx
    print("<--   Done. total:", sum_times, "; per tx:", merkle_proof_timing[-1])
    
    print("--> prove membership accumulator")
    times = []
    acc_mem_proofs = []
    for i in range(num_of_txs_in_block):
        tik = time.time()
        inputs_list = []
        for j in range(num_of_inputs_in_tx):
            inputs_list.append(inputs_for_accumulator[num_of_inputs_in_tx * i + j])
        acc_mem_proofs.append(batch_prove_membership(A0, S, inputs_list, n))
        tok = time.time()
        times.append(tok - tik)
    sum_times = sum(times)
    acc_batch_prove_mem_timing.append(sum_times / len(times))  # average
    print("<--   Done. total:", sum_times, "; per tx:", acc_batch_prove_mem_timing[-1])

    print("--> prove membership accumulator with NI-PoE")
    times = []
    acc_mem_proofs_with_NIPoE = []
    for i in range(num_of_txs_in_block):
        tik = time.time()
        inputs_list = []
        for j in range(num_of_inputs_in_tx):
            inputs_list.append(inputs_for_accumulator[num_of_inputs_in_tx * i + j])
        acc_mem_proofs_with_NIPoE.append(batch_prove_membership_with_NIPoE(A0, S, inputs_list, n, A_post_batch_add))
        tok = time.time()
        times.append(tok - tik)
    sum_times = sum(times)
    acc_batch_prove_mem_with_NIPoE_timing.append(sum_times / len(times))  # average
    print("<--   Done. total:", sum_times, "; per tx:", acc_batch_prove_mem_with_NIPoE_timing[-1])

    print("--> Merkle tree verify membership")
    merkle_root = merkle_tree.get_merkle_root()
    merkle_leaves = []
    for i in range(num_of_inputs_in_tx * num_of_txs_in_block):
        merkle_leaves.append(merkle_tree.get_leaf(i))

    tik = time.time()
    for i in range(num_of_txs_in_block):
        for j in range(num_of_inputs_in_tx):
            assert merkle_tree.validate_proof(merkle_proofs[i], merkle_leaves[i], merkle_root)
    tok = time.time()
    merkle_verify_mem_per_block_timing.append(tok - tik)
    merkle_verify_mem_per_tx_timing.append((tok - tik) / num_of_txs_in_block)  # average
    print("<--   Done. total (per block):", merkle_verify_mem_per_block_timing[-1], "; per tx:", merkle_verify_mem_per_tx_timing[-1])

    print("--> accumulator batch verify membership")
    tik = time.time()
    for i in range(num_of_txs_in_block):
        inputs_list = []
        for j in range(num_of_inputs_in_tx):
            inputs_list.append(inputs_for_accumulator[num_of_inputs_in_tx * i + j])
        # TODO: nonces should be given by the proofs?
        nonces_list = list(map(lambda x: S[x], inputs_list))
        assert batch_verify_membership(A_post_batch_add, inputs_list, nonces_list, acc_mem_proofs[i], n)
    tok = time.time()
    acc_batch_verify_mem_per_block_timing.append(tok - tik)
    acc_batch_verify_mem_per_tx_timing.append((tok - tik) / num_of_txs_in_block)  # average
    print("<--   Done. total (per block):", acc_batch_verify_mem_per_block_timing[-1], "; per tx:", acc_batch_verify_mem_per_tx_timing[-1])

    print("--> accumulator batch verify membership with NIPoE")
    tik = time.time()
    for i in range(num_of_txs_in_block):
        inputs_list = []
        for j in range(num_of_inputs_in_tx):
            inputs_list.append(inputs_for_accumulator[num_of_inputs_in_tx * i + j])
        # TODO: nonces should be given by the proofs?
        nonces_list = list(map(lambda x: S[x], inputs_list))
        assert batch_verify_membership_with_NIPoE(
            acc_mem_proofs_with_NIPoE[i][0],
            acc_mem_proofs_with_NIPoE[i][1],
            acc_mem_proofs_with_NIPoE[i][2],
            inputs_list,
            nonces_list,
            A_post_batch_add,
            n)
    tok = time.time()
    acc_batch_verify_mem_with_NIPoE_per_block_timing.append(tok - tik)
    acc_batch_verify_mem_with_NIPoE_per_tx_timing.append((tok - tik) / num_of_txs_in_block)  # average
    print("<--   Done. total (per block):", acc_batch_verify_mem_with_NIPoE_per_block_timing[-1], "; per tx:", acc_batch_verify_mem_with_NIPoE_per_tx_timing[-1])

    print("--> accumulator batch delete spent TXOs + first NI-PoE")
    tik = time.time()
    agg_inputs_indexes = []
    for i in range(num_of_txs_in_block):
        agg_inputs_indexes.append([num_of_inputs_in_tx * i, num_of_inputs_in_tx * (i + 1)])
    # TODO: can we get the NI-PoE proofs here?
    A_post_batch_delete, niope1 = batch_delete_using_membership_proofs(A_post_batch_add, S, inputs_for_accumulator, acc_mem_proofs, n, agg_inputs_indexes)
    tok = time.time()
    acc_batch_delete_timing.append(tok - tik)
    print("<--   Done.", acc_batch_delete_timing[-1])

    print("--> accumulator batch add new UTXOs + second NI-PoE")
    tik = time.time()
    A_post_batch_add_new, niope2 = batch_add(A_post_batch_delete, S, outputs_for_accumulator, n)
    outputs_nonces_list = [S[x] for x in outputs_for_accumulator]
    tok = time.time()
    acc_batch_add_per_block_timing.append(tok - tik)
    print("<--   Done.", acc_batch_add_per_block_timing[-1])

    print("--> accumulator verify first NI-PoE & second NI-PoE")
    tik = time.time()
    assert batch_verify_membership_with_NIPoE(niope1[0], niope1[1], A_post_batch_delete, inputs_for_accumulator, inputs_nonces_list, A_post_batch_add, n)
    assert batch_verify_membership_with_NIPoE(niope2[0], niope2[1], A_post_batch_delete, outputs_for_accumulator, outputs_nonces_list, A_post_batch_add_new, n)
    tok = time.time()
    acc_batch_verify_two_NIPoE_post_mining.append(tok - tik)
    print("<--   Done.", acc_batch_verify_two_NIPoE_post_mining[-1])
    

num_of_txs_in_block = []
for i in range(5):
    num_of_txs_in_block.append((i + 1) * 20)
    test_mining(
        total_utxo_set_size_for_merkle_tree=pow(2, 20),
        total_utxo_set_size_for_accumulator=num_of_txs_in_block[i] * 3,
        num_of_inputs_in_tx=3,
        num_of_outputs_in_tx=3,
        num_of_txs_in_block=num_of_txs_in_block[i])

num_of_txs_in_block = [''] + num_of_txs_in_block

with open(GENERATED_CSV_DIRECTORY + '/proofs-per-tx.csv', mode='w') as csv_file:
    csv_file = csv.writer(csv_file, delimiter=',', quotechar='"', quoting=csv.QUOTE_MINIMAL)
    csv_file.writerow(num_of_txs_in_block)
    csv_file.writerow(['Merkle Tree'] + merkle_proof_timing)
    csv_file.writerow(['Accumulator: Aggregate'] + acc_batch_prove_mem_timing)
    csv_file.writerow(['Accumulator: Aggregate w. NI-PoE'] + acc_batch_prove_mem_with_NIPoE_timing)

with open(GENERATED_CSV_DIRECTORY + '/verifications-per-tx.csv', mode='w') as csv_file:
    csv_file = csv.writer(csv_file, delimiter=',', quotechar='"', quoting=csv.QUOTE_MINIMAL)
    csv_file.writerow(num_of_txs_in_block)
    csv_file.writerow(['Merkle Tree'] + merkle_verify_mem_per_tx_timing)
    csv_file.writerow(['Accumulator: Batch'] + acc_batch_verify_mem_per_tx_timing)
    csv_file.writerow(['Accumulator: Batch w. NI-PoE'] + acc_batch_verify_mem_with_NIPoE_per_tx_timing)

with open(GENERATED_CSV_DIRECTORY + '/verifications-per-block.csv', mode='w') as csv_file:
    csv_file = csv.writer(csv_file, delimiter=',', quotechar='"', quoting=csv.QUOTE_MINIMAL)
    csv_file.writerow(num_of_txs_in_block)
    csv_file.writerow(['Merkle Tree'] + merkle_verify_mem_per_block_timing)
    csv_file.writerow(['Accumulator: Batch'] + acc_batch_verify_mem_per_block_timing)
    csv_file.writerow(['Accumulator: Batch w. NI-PoE'] + acc_batch_verify_mem_with_NIPoE_per_block_timing)

with open(GENERATED_CSV_DIRECTORY + '/batch-delete-per-block.csv', mode='w') as csv_file:
    csv_file = csv.writer(csv_file, delimiter=',', quotechar='"', quoting=csv.QUOTE_MINIMAL)
    csv_file.writerow(num_of_txs_in_block)
    csv_file.writerow(['Accumulator: Batch Delete'] + acc_batch_delete_timing)

with open(GENERATED_CSV_DIRECTORY + '/batch-add-per-block.csv', mode='w') as csv_file:
    csv_file = csv.writer(csv_file, delimiter=',', quotechar='"', quoting=csv.QUOTE_MINIMAL)
    csv_file.writerow(num_of_txs_in_block)
    csv_file.writerow(['Accumulator: Batch Add'] + acc_batch_add_per_block_timing)

with open(GENERATED_CSV_DIRECTORY + '/batch-verify-aggregated-two-niopes.csv', mode='w') as csv_file:
    csv_file = csv.writer(csv_file, delimiter=',', quotechar='"', quoting=csv.QUOTE_MINIMAL)
    csv_file.writerow(num_of_txs_in_block)
    csv_file.writerow(['Accumulator: Verify 2 NIPoEs'] + acc_batch_verify_two_NIPoE_post_mining)

print('Done - written results to ' + os.path.dirname(os.path.abspath(__file__)) + '/' + GENERATED_CSV_DIRECTORY)
