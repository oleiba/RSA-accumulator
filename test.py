import secrets
import math
from helpfunctions import hash_to_prime, is_prime, shamir_trick
from finalproject import setup, add_element, prove_membership, delete_element, verify_membership, \
        prove_membership_with_NIPoE, verify_exponentiation, batch_prove_membership, batch_verify_membership, \
        batch_prove_membership_with_NIPoE, batch_verify_membership_with_NIPoE, add_elements
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
                A1 = add_element(A0, S, x0, n)
                nonce = S[x0]

                proof = prove_membership(A0, S, x0, n)
                self.assertEqual(len(S), 1)
                self.assertEqual(A0, proof)
                self.assertTrue(verify_membership(A1, x0, nonce, proof, n))

                # second addition
                A2 = add_element(A1, S, x1, n)
                nonce = S[x1]

                proof = prove_membership(A0, S, x1, n)
                self.assertEqual(len(S), 2)
                self.assertEqual(A1, proof)
                self.assertTrue(verify_membership(A2, x1, nonce, proof, n))

                # delete
                A1_new = delete_element(A0, A2, S, x0, n)
                proof = prove_membership(A0, S, x1, n)
                proof_none = prove_membership(A0, S, x0, n)
                self.assertEqual(len(S), 1)
                self.assertEqual(proof_none, None)
                self.assertTrue(verify_membership(A1_new, x1, nonce, proof, n))

        def test_add_elements(self):
                n, A0, S = setup()

                x0 = secrets.randbelow(pow(2, 256))
                x1 = secrets.randbelow(pow(2, 256))
                x2 = secrets.randbelow(pow(2, 256))
                x3 = secrets.randbelow(pow(2, 256))
                x4 = secrets.randbelow(pow(2, 256))

                # first addition
                Abacth = add_elements(A0, S, [x0,x1,x2,x3,x4], n)
                A = Abacth
                Adel0 = delete_element(A0, A, S, x0, n)
                Adel1 = delete_element(A0, Adel0, S, x1, n)
                Adel2 = delete_element(A0, Adel1, S, x2, n)
                Adel3 = delete_element(A0, Adel2, S, x3, n)
                Adel4 = delete_element(A0, Adel3, S, x4, n)
                self.assertEqual(A0, Adel4)

                Aadd0 = add_element(Adel4, S, x0, n)
                Aadd1 = add_element(Aadd0, S, x1, n)
                Aadd2 = add_element(Aadd1, S, x2, n)
                Aadd3 = add_element(Aadd2, S, x3, n)
                Aadd4 = add_element(Aadd3, S, x4, n)

                self.assertEqual(Aadd4, Abacth)

        def test_proof_of_exponent(self):
                # first, do regular accumulation
                n, A0, S = setup()
                x0 = secrets.randbelow(pow(2, 256))
                x1 = secrets.randbelow(pow(2, 256))
                A1 = add_element(A0, S, x0, n)
                A2 = add_element(A1, S, x1, n)

                Q, l_nonce, u = prove_membership_with_NIPoE(A0, S, x0, n, A2)
                is_valid = verify_exponentiation(Q, l_nonce, u, x0, S[x0], A2, n)
                self.assertTrue(is_valid)

        def test_batch_proof_of_membership(self):
                n, A0, S = setup()

                elements_list = create_list(10)

                A = A0
                for x in elements_list:
                        A = add_element(A, S, x, n)
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
                        A = add_element(A, S, x, n)
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

                agg_proof = shamir_trick(prime0, proof0, prime1, proof1, n)
                power = pow(agg_proof, prime0 * prime1, n)

                is_valid = power == A2
                self.assertTrue(is_valid)

        def test_shamir_trick_2(self):
                n, A0, S = setup()

                elements_list = create_list(2)

                A1 = add_element(A0, S, elements_list[0], n)
                A2 = add_element(A1, S, elements_list[1], n)

                prime0 = hash_to_prime(elements_list[0], nonce=S[elements_list[0]])[0]
                prime1 = hash_to_prime(elements_list[1], nonce=S[elements_list[1]])[0]

                proof0 = prove_membership(A0, S, elements_list[0], n)
                proof1 = prove_membership(A0, S, elements_list[1], n)

                agg_proof = shamir_trick(prime0, proof0, prime1, proof1, n)

                is_valid = pow(agg_proof, prime0 * prime1, n) == A2
                self.assertTrue(is_valid)
