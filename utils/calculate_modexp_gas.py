import math
from unittest import TestCase

GQUADDIVISOR = 20


# EIP198 gas calculation. All lengths in bytes.
def calculate_gas_consumption(length_of_base, length_of_exponent, length_of_modulus, exponent):
    return math.floor(mult_complexity(max(length_of_modulus, length_of_base)) * max(adjusted_exponent_length(length_of_exponent, exponent), 1) / GQUADDIVISOR)


def adjusted_exponent_length(length_of_exponent, exponent):
    print('adjusted_exponent_length(' + str(length_of_exponent) + ', ' + str(exponent) + ')')
    if exponent == 0:
        return 0
    elif length_of_exponent <= 32:
        # return the index of the highest bit in exponent
        print('#1, returning: ' + str(len(bin(exponent)) - 2))
        return len(bin(exponent)) - 3  # first two characters are '0b' prefix
    else:
        length_of_exponent_bits = length_of_exponent * 8
        exponent_binary = format(exponent, '#0' + str(length_of_exponent_bits + 2) + 'b')  # +2 for '0b' prefix
        exponent_first_256_bits = exponent_binary[2:258]
        highest_bit_in_exponent_first_256_bits = 0 if exponent == 0 else 255 - exponent_first_256_bits.find('1')
        return 8 * (length_of_exponent - 32) + highest_bit_in_exponent_first_256_bits


def mult_complexity(x):
    if x <= 64: return x ** 2
    elif x <= 1024: return x ** 2 // 4 + 96 * x - 3072
    else: return x ** 2 // 16 + 480 * x - 199680


# Testcases from EIP198
class CalculateGasTest(TestCase):
    def test_adjusted_exponent_length(self):
        exponent = pow(2, 100*8 - 3)
        self.assertEqual(adjusted_exponent_length(100, exponent), 797)

    def test_calculate_gas_consumption(self):
        length_of_base = 1
        length_of_exponent = 32
        length_of_modulus = 32
        base = 3
        exponent = int('fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2e', 16)
        modulus = int('fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f', 16)
        self.assertEqual(calculate_gas_consumption(length_of_base, length_of_exponent, length_of_modulus, exponent), 13056)
