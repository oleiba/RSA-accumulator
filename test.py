import secrets
from finalproject import setup, add_element, prove_membership, delete_element, verify
from unittest import TestCase


class AccumulatorTest(TestCase):
        def test_add_element(self):
                n, A0, S = setup()

                x0 = secrets.randbelow(pow(2,256))
                x1 = secrets.randbelow(pow(2,256))

                # first addition
                A1 = add_element(A0, S, x0, n)
                nonce = dict(S)[x0]

                proof = prove_membership(A0, S, x0, n)
                self.assertEqual(len(S), 1)
                self.assertEqual(A0, proof)
                self.assertEqual(verify(A1, x0, nonce, proof, n), True)

                # second addition
                A2 = add_element(A1, S, x1, n)
                nonce = dict(S)[x1]

                proof = prove_membership(A0, S, x1, n)
                self.assertEqual(len(S), 2)
                self.assertEqual(A1, proof)
                self.assertEqual(verify(A2, x1, nonce, proof, n), True)

