# -*- coding: utf-8 -*-

import random
import hashlib
import base58


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
    first_sha = hashlib.sha256(bytearray.fromhex(private_key_and_version)).hexdigest().upper()
    second_sha = hashlib.sha256(bytearray.fromhex(first_sha)).hexdigest().upper()
    checksum = second_sha[:8]
    private_key_with_checksum = private_key_and_version + checksum
    private_key_wif = base58.b58encode(str(bytearray.fromhex(private_key_with_checksum)))

    return private_key_wif


def wif_to_pk(wif):
    print wif
    byte_string = base58.b58decode_check(wif)
    print byte_string
    checksum = byte_string[-8:]

    first_sha = hashlib.sha256(byte_string[0:-8]).hexdigest()
    second_sha = hashlib.sha256(first_sha).hexdigest()

    if checksum == second_sha[:8] and byte_string[0:1] == '80':
        return byte_string[2:-8]

    raise ValueError('Invalid WIF')



