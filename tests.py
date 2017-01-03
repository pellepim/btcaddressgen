# -*- coding: utf-8 -*-

import unittest
import gen


class PrivateKeyTests(unittest.TestCase):
    def test_private_key_correct_length(self):
        """ The private key should be 32 bytes long """
        self.assertTrue(len(gen.private_key()), 32)

    def test_private_key_correct_content(self):
        """ Each member of the private key should be a byte"""
        private_key = gen.private_key()

        for b in private_key:
            self.assertTrue(isinstance(b, int))
            self.assertTrue(0 <= b <= 255)


class PrivateHexKeyTests(unittest.TestCase):
    def setUp(self):
        self.mocked_private_key = [i for i in range(32)]
        self.expected_hex = '000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F'

    def test_expected(self):
        """ Test that a hexadecimal representation is successfully generated from a private key """
        self.assertEqual(self.expected_hex, gen.private_hex(self.mocked_private_key))

    def test_new(self):
        """ Test that we can generate a hex representation private key randomly """

        actual = gen.private_hex()

        self.assertEqual(len(bytearray.fromhex(actual)), 32)  # The private key ought to be 32 bytes long

        for b in bytearray.fromhex(actual):
            self.assertTrue(isinstance(b, int))
            self.assertTrue(0 <= b <= 255)


class PrivateWIFKeyTests(unittest.TestCase):
    def setUp(self):
        self.mocked_hex = '0C28FCA386C7A227600B2FE50B7CAE11EC86D3BF1FBE471BE89827E19D72AA1D'
        self.expected_wif = '5HueCGU8rMjxEXxiPuD5BDku4MkFqeZyd4dZ1jvhTVqvbTLvyTJ'

    def test_expected(self):
        """ Test that a WIF private key is reliably generated based on a certain hex formatted private key"""
        actual = gen.private_wif(self.mocked_hex)

        self.assertEqual(self.expected_wif, actual)

    def test_new(self):
        """ Test that we can generate a new WIF private key randomly """
        private_wif = gen.private_wif()

        self.assertEqual(len(private_wif), 51)


class WIFToPKTests(unittest.TestCase):
    def setUp(self):
        self.mocked_wif = '5HueCGU8rMjxEXxiPuD5BDku4MkFqeZyd4dZ1jvhTVqvbTLvyTJ'
        self.expected_hex = '0C28FCA386C7A227600B2FE50B7CAE11EC86D3BF1FBE471BE89827E19D72AA1D'

    def test(self):
        self.assertEquals(gen.wif_to_pk(self.mocked_wif), self.expected)

if __name__ == '__main__':
    unittest.main()
