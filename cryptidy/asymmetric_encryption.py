#! /usr/bin/env python
#  -*- coding: utf-8 -*-
#
# This file is part of cryptidy module

"""
Asymmetric encryption using RSA private + public keys that encrypt a session key for
AES-256 symmetric encryption routines based on pycryptodomex / pycryptodome
This library may encrypt / decrypt strings, bytes or python objects that support pickling

Versioning semantics:
    Major version: backward compatibility breaking changes
    Minor version: New functionality
    Patch version: Backwards compatible bug fixes

"""

__intname__ = 'cryptidy.asymmetric_encryption'
__author__ = 'Orsiris de Jong'
__copyright__ = 'Copyright (C) 2020-2021 Orsiris de Jong'
__licence__ = 'BSD 3 Clause'
__version__ = '1.0.4'
__build__ = '202101201'


import sys
from logging import getLogger
from base64 import b64encode, b64decode
from binascii import Error as binascii_Error
from datetime import datetime
from Cryptodome.PublicKey import RSA
from Cryptodome.Random import get_random_bytes
from Cryptodome.Cipher import PKCS1_OAEP
# Make sure we use a solid Hash algorithm, industry standard is SHA256, don't use SHA3 yet as of Nov 2020
from Cryptodome.Hash import SHA384 as HASH_ALGO
# Try to import as absolute when used as module, import as relative for autotests
try:
    from cryptidy.symmetric_encryption import aes_encrypt_message, aes_decrypt_message
except ImportError:
    from .symmetric_encryption import aes_encrypt_message, aes_decrypt_message
# Python 2.7 compat fixes (missing typing and FileNotFoundError)
try:
    from typing import Any, Tuple, Union
except ImportError:
    pass
# Python 2 fix where RSA keys are 'unicode' type, which does not exist in Python 3 anymore
# Python 2 has a class 'basestring' which includes all string types
if sys.version_info[0] < 3:
    # pylint: disable=E0602,undefined-variable
    string_type = basestring  # noqa: F821
else:
    string_type = str

logger = getLogger(__name__)


def generate_keys(length=2048):
    # type: (int) -> Tuple[str, str]
    """
    RSA key pair generator

    :param length: key size, can be 1024, 2048 or 4096 bits
    :return: (tuple) private_key, public_key as PEM format
    """
    if length < 1024:
        raise ValueError('RSA key length must be >= 1024')
    private_key = RSA.generate(length)
    public_key = private_key.publickey()
    return private_key.export_key().decode(), public_key.export_key().decode()


def verify_private_key(private_key):
    # type: (str) -> None
    """
    Simple key type verification to make decryption debugging easier
    """
    if private_key is None:
        raise TypeError('No private key provided.')

    if not isinstance(private_key, string_type):
        raise TypeError('Wrong private key provided. PEM encoded key should be passed, not bytes.')
    if '-----BEGIN RSA PRIVATE KEY-----\n' not in private_key:
        raise TypeError('Wrong private key provided. Does not look like a PEM encoded key.')


def verify_public_key(public_key):
    # type: (str) -> None
    """
    Simple key type verification to make decryption debugging easier
    """
    if public_key is None:
        raise TypeError('No private key provided.')

    if not isinstance(public_key, string_type):
        raise TypeError('Wrong private key provided. PEM encoded key should be passed, not bytes.')
    if '-----BEGIN PUBLIC KEY-----\n' not in public_key:
        raise TypeError('Wrong private key provided. Does not look like a PEM encoded key.')


def encrypt_message(msg, public_key):
    # type: (Any, str) -> bytes
    """
    Simple base64 wrapper for rsa_encrypt_message

    :param msg: original encrypted message
    :param public_key: rsa public key
    :return: (bytes) base64 encoded aes encrypted message
    """
    verify_public_key(public_key)
    return b64encode(rsa_encrypt_message(msg, public_key))


def rsa_encrypt_message(msg, public_key):
    # type: (Any, str) -> bytes
    """
    RSA encrypt a python object / bytes / string and add an encryption timestamp

    :param msg: original data
    :param public_key: rsa public key
    :return: (bytes): encrypted data
    """
    # Note: No need to pickle the message, since this will be done in symmetric encryption

    # Triggers ValueError on invalid pubkey
    public_key = RSA.import_key(public_key)
    cipher_rsa = PKCS1_OAEP.new(key=public_key, hashAlgo=HASH_ALGO)

    # Let's create an aes encryption key based on the RSA pubkey size
    session_key_size = int(public_key.size_in_bits() / 64)
    # Allowed Cryptodomex session_key_sizes are 16, 24 and 32
    session_key_size = 32 if session_key_size > 32 else session_key_size
    session_key = get_random_bytes(session_key_size)

    # RSA encrypt the aes encryption key and use the original key to encrypt our message using AES
    enc_session_key = cipher_rsa.encrypt(session_key)
    return enc_session_key + aes_encrypt_message(msg, session_key)


def decrypt_message(msg, private_key):
    # type: (Union[bytes, str], str) -> Tuple[datetime, Any]
    """
    Simple base64 wrapper for rsa_decrypt_message

    :param msg: b64 encoded original rsa encrypted data
    :param private_key: rsa private key
    :return: (bytes): rsa decrypted data
    """
    verify_private_key(private_key)
    try:
        decoded_msg = b64decode(msg)
    except (TypeError, binascii_Error):
        raise TypeError('decrypt_message accepts b64 encoded byte objects')

    return rsa_decrypt_message(decoded_msg, private_key)


def rsa_decrypt_message(msg, private_key):
    # type: (bytes, str) -> Tuple[datetime, Any]
    """
    RSA decrypt a python object / bytes / string and check the encryption timestamp

    :param msg: original rsa encrypted data
    :param private_key: rsa encryption key
    :return: original data
    """
    private_key = RSA.import_key(private_key)
    enc_session_key_size = int(private_key.size_in_bits() / 8)

    cipher_rsa = PKCS1_OAEP.new(key=private_key, hashAlgo=HASH_ALGO)
    enc_session_key, aes_encrypted_msg = \
        (msg[0:enc_session_key_size], msg[enc_session_key_size:])
    try:
        session_key = cipher_rsa.decrypt(enc_session_key)
    except TypeError:
        raise TypeError('You need a private key to decrypt data.')
    except ValueError:
        raise ValueError('RSA Integrity check failed, cannot decrypt data.')

    return aes_decrypt_message(aes_encrypted_msg, session_key)
