# -*- coding: ascii -*-

import random
import bitcoin
import base58
from pybitcoin import BitcoinPrivateKey


def private_key():
    """
    Returns a 256 bit long random number or in layman terms, 32 random bytes.
    """
    p_key = []

    for i in range(32):
        p_key.append(random.SystemRandom(random.randint(0, 255)).randint(0, 255))

    return p_key


def private_hex(p_key=None):
    """
    Formats a private key to hexadecimal format, if no private key is provided an new one is randomized
    """
    if p_key is None:
        p_key = private_key()

    prv_hex = ''.join('{:02X}'.format(b) for b in p_key)
    return prv_hex


def private_wif(p_key_hex=None):
    """
    Generates a private key formatted according to the Wallet Import Format (WIF) based on a private key hex.

    If not private key hex is provided, a new one is randomized.
    """

    if p_key_hex is None:
        p_key_hex = private_hex()

    private_key_and_version = '80' + p_key_hex
    private_key_wif = base58.b58encode_check(str(bytearray.fromhex(private_key_and_version)))

    return private_key_wif


def wif_to_pk(wif):
    """
    Returns a 32 byte long private key based on a supplied Wallet Input Format string.
    """
    byte_string = base58.b58decode_check(wif)
    return [ord(b) for b in byte_string][1:]


def wif_to_pk_hex(wif):
    """
    Returns a hex private key based on a supplied Wallet Input Format string
    """
    return private_hex(wif_to_pk(wif))


def public_key(pk=None, wif=None, _hex=None):
    if (pk is None and wif is None and _hex is None) or (pk and wif and _hex):
        raise RuntimeError('Supply either private key either as bytearray (pk) or in Wallet Input Format (wif), not both.')

    if wif:
        pk = wif_to_pk(wif)

    if pk:
        _hex = private_hex(pk)

    return BitcoinPrivateKey(_hex).public_key().address()

print BitcoinPrivateKey('0C28FCA386C7A227600B2FE50B7CAE11EC86D3BF1FBE471BE89827E19D72AA1D').public_key().address()











