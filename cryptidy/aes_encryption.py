#! /usr/bin/env python
#  -*- coding: utf-8 -*-
#
# This file is part of cryptidy module

"""
Simple AES encryption wrapper used by symmetric and asymmetric encryption modules

Versioning semantics:
    Major version: backward compatibility breaking changes
    Minor version: New functionality
    Patch version: Backwards compatible bug fixes

"""

__intname__ = "cryptidy.aes_encryption"
__author__ = "Orsiris de Jong"
__copyright__ = "Copyright (C) 2018-2024 Orsiris de Jong"
__licence__ = "BSD 3 Clause"
__version__ = "1.2.3"
__build__ = "2024101801"

import sys
from logging import getLogger
import string
import random
from Cryptodome.Cipher import AES  # pylint: disable=I0021,import-error
from Cryptodome.Random import get_random_bytes  # pylint: disable=I0021,import-error

# Python 2.7 compat fixes (missing typing and FileNotFoundError)
try:
    from typing import Union, Tuple
except ImportError:
    pass

logger = getLogger()


def generate_key(size=32):
    # type: (int) -> bytes
    """
    AES key generator


    :param size: (int) key size, can be 16, 24 or 32 bytes
    :return: (bytes) aes key
    """
    try:
        aes_key = get_random_bytes(size)
        return aes_key
    except Exception as exc:  # pylint: disable=W0703,broad-except
        raise ValueError(
            "Cannot generate AES key: %s" % exc
        )  # pylint: disable=W0707,raise-missing-from


def aes_encrypt(msg, aes_key):
    # type: (bytes, bytes) -> Tuple[Union[bytes, bytearray, memoryview], bytes, bytes]
    """
    Encrypt a bytes message

    :param msg:  Message to encrypt
    :param aes_key: AES encryption key

    :return: (tuple) encrypted message composed of nonce, tag and ciphertext
    """
    try:
        if aes_key is not None:
            cipher = AES.new(aes_key, AES.MODE_EAX)
            # wipe key from memory as soon as it's been used
            aes_key = None
        else:
            raise ValueError("No AES key provided.")

        ciphertext, tag = cipher.encrypt_and_digest(msg)
        return cipher.nonce, tag, ciphertext
    except Exception as exc:  # pylint: disable=W0703,broad-except
        # goodenough(TM) Magic to avoid SyntaxError on PEP-0409 statements in Python < 3.3
        err = 'raise ValueError("Encrypt failed: {}")'.format(exc)
        if sys.version_info[0] < 3 or (
            sys.version_info[0] == 3 and sys.version_info[1] < 4
        ):
            exec(err)
        else:
            exec(err + " from None")


def aes_decrypt(aes_key, nonce, tag, ciphertext):
    # type: (bytes, bytes, bytes, bytes) -> bytes
    """
    Decrypt a bytes message

    :param aes_key: AES encryption key
    :param nonce: encryption nonce
    :param tag: encryption tag
    :param ciphertext: message to decrypt
    :return: (bytes) original message
    """

    try:
        if aes_key is not None:
            cipher = AES.new(aes_key, AES.MODE_EAX, nonce)
            # wipe key from memory as soon as it's been used
            aes_key = None
        else:
            raise ValueError("No aes key provided.")

        data = cipher.decrypt_and_verify(ciphertext, tag)
        return data
    except Exception as exc:  # pylint: disable=W0703,broad-except
        # goodenough(TM) Magic to avoid SyntaxError on PEP-0409 statements in Python < 3.3
        err = 'raise ValueError("Decrypt failed: {}")'.format(exc)
        if sys.version_info[0] < 3 or (
            sys.version_info[0] == 3 and sys.version_info[1] < 4
        ):
            exec(err)
        else:
            exec(err + " from None")


def generate_random_string(size=8, chars=string.ascii_letters + string.digits):
    # type: (int, list) -> str
    """
    Simple random base64 like string from ofunctions.random
    """
    return "".join(random.choice(chars) for _ in range(size))
