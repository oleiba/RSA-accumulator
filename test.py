import secrets
import math
from helpfunctions import hash_to_prime, is_prime, shamir_trick
from main import setup, add, prove_membership, delete, verify_membership, \
        prove_membership_with_NIPoE, verify_exponentiation, batch_prove_membership, batch_verify_membership, \
        batch_prove_membership_with_NIPoE, batch_verify_membership_with_NIPoE, batch_add, \
        prove_non_membership, verify_non_membership, batch_delete, batch_delete_using_membership_proofs
from unittest import TestCase


def create_list(size):
        res = []
        for i in range(size):
                x = secrets.randbelow(pow(2, 256))
                res.append(x)
        return res


class AccumulatorTest(TestCase):
        def test_hash_to_prime(self):
                x = secrets.randbelow(pow(2, 256))
                h, nonce = hash_to_prime(x, 128)
                self.assertTrue(is_prime(h))
                self.assertTrue(h, math.log2(h) < 128)

        def test_add_element(self):
                n, A0, S = setup()

                x0 = secrets.randbelow(pow(2, 256))
                x1 = secrets.randbelow(pow(2, 256))

                # first addition
                A1 = add(A0, S, x0, n)
                nonce = S[x0]

                proof = prove_membership(A0, S, x0, n)
                self.assertEqual(len(S), 1)
                self.assertEqual(A0, proof)
                self.assertTrue(verify_membership(A1, x0, nonce, proof, n))

                # second addition
                A2 = add(A1, S, x1, n)
                nonce = S[x1]

                proof = prove_membership(A0, S, x1, n)
                self.assertEqual(len(S), 2)
                self.assertEqual(A1, proof)
                self.assertTrue(verify_membership(A2, x1, nonce, proof, n))

                # delete
                A1_new = delete(A0, A2, S, x0, n)
                proof = prove_membership(A0, S, x1, n)
                proof_none = prove_membership(A0, S, x0, n)
                self.assertEqual(len(S), 1)
                self.assertEqual(proof_none, None)
                self.assertTrue(verify_membership(A1_new, x1, nonce, proof, n))

        def test_proof_of_exponent(self):
                # first, do regular accumulation
                n, A0, S = setup()
                x0 = secrets.randbelow(pow(2, 256))
                x1 = secrets.randbelow(pow(2, 256))
                A1 = add(A0, S, x0, n)
                A2 = add(A1, S, x1, n)

                Q, l_nonce, u = prove_membership_with_NIPoE(A0, S, x0, n, A2)
                is_valid = verify_exponentiation(Q, l_nonce, u, x0, S[x0], A2, n)
                self.assertTrue(is_valid)

        def test_batch_add(self):
                n, A0, S = setup()

                elements_list = create_list(10)

                A_post_add, nipoe = batch_add(A0, S, elements_list, n)
                self.assertEqual(len(S), 10)

                nonces_list = list(map(lambda e: hash_to_prime(e)[1], elements_list))
                is_valid = batch_verify_membership_with_NIPoE(nipoe[0], nipoe[1], A0, elements_list, nonces_list, A_post_add, n)
                self.assertTrue(is_valid)

        def test_batch_proof_of_membership(self):
                n, A0, S = setup()

                elements_list = create_list(10)

                A = A0
                for x in elements_list:
                        A = add(A, S, x, n)
                A_final = A

                elements_to_prove_list = [elements_list[4], elements_list[7], elements_list[8]]
                A_intermediate = batch_prove_membership(A0, S, elements_to_prove_list, n=n)
                nonces_list = list(map(lambda e: hash_to_prime(e)[1], elements_to_prove_list))
                is_valid = batch_verify_membership(A_final, elements_to_prove_list, nonces_list, A_intermediate, n)
                self.assertTrue(is_valid)

        def test_batch_proof_of_membership_with_NIPoE(self):
                n, A0, S = setup()

                elements_list = create_list(10)

                A = A0
                for x in elements_list:
                        A = add(A, S, x, n)
                A_final = A

                elements_to_prove_list = [elements_list[4], elements_list[7], elements_list[8]]
                Q, l_nonce, u = batch_prove_membership_with_NIPoE(A0, S, elements_to_prove_list, n, A_final)
                nonces_list = list(map(lambda e: hash_to_prime(e)[1], elements_to_prove_list))
                is_valid = batch_verify_membership_with_NIPoE(Q, l_nonce, u, elements_to_prove_list, nonces_list, A_final, n)
                self.assertTrue(is_valid)

        def test_shamir_trick_1(self):
                n = 23
                A0 = 2

                prime0 = 3
                prime1 = 5

                A1 = pow(A0, prime0, n)
                A2 = pow(A1, prime1, n)

                proof0 = pow(A0, prime1, n)
                proof1 = pow(A0, prime0, n)

                agg_proof = shamir_trick(proof0, proof1, prime0, prime1, n)
                power = pow(agg_proof, prime0 * prime1, n)

                is_valid = power == A2
                self.assertTrue(is_valid)

        def test_shamir_trick_2(self):
                n, A0, S = setup()

                elements_list = create_list(2)

                A1 = add(A0, S, elements_list[0], n)
                A2 = add(A1, S, elements_list[1], n)

                prime0 = hash_to_prime(elements_list[0], nonce=S[elements_list[0]])[0]
                prime1 = hash_to_prime(elements_list[1], nonce=S[elements_list[1]])[0]

                proof0 = prove_membership(A0, S, elements_list[0], n)
                proof1 = prove_membership(A0, S, elements_list[1], n)

                agg_proof = shamir_trick(proof0, proof1, prime0, prime1, n)

                is_valid = pow(agg_proof, prime0 * prime1, n) == A2
                self.assertTrue(is_valid)

        def test_prove_non_membership(self):
                n, A0, S = setup()

                elements_list = create_list(3)

                A1 = add(A0, S, elements_list[0], n)
                A2 = add(A1, S, elements_list[1], n)
                A3 = add(A2, S, elements_list[2], n)

                proof = prove_non_membership(A0, S, elements_list[0], S[elements_list[0]], n)
                self.assertIsNone(proof)

                x = create_list(1)[0]
                prime, x_nonce = hash_to_prime(x)
                proof = prove_non_membership(A0, S, x, x_nonce, n)
                is_valid = verify_non_membership(A0, A3, proof[0], proof[1], x, x_nonce, n)
                self.assertTrue(is_valid)

        def test_batch_delete(self):
                n, A0, S = setup()

                elements_list = create_list(5)

                A = A0
                for i in range(len(elements_list)):
                        A = add(A, S, elements_list[i], n)
                A_pre_delete = A

                elements_to_delete_list = [elements_list[0], elements_list[2], elements_list[4]]
                nonces_list = list(map(lambda e: hash_to_prime(e)[1], elements_to_delete_list))

                proofs = list(map(lambda x: prove_membership(A0, S, x, n), elements_to_delete_list))

                A_post_delete, nipoe = batch_delete_using_membership_proofs(A_pre_delete, S, elements_to_delete_list, proofs, n)

                is_valid = batch_verify_membership_with_NIPoE(nipoe[0], nipoe[1], A_post_delete, elements_to_delete_list, nonces_list, A_pre_delete, n)
                self.assertTrue(is_valid)
