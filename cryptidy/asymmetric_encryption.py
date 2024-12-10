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

__intname__ = "cryptidy.asymmetric_encryption"
__author__ = "Orsiris de Jong"
__copyright__ = "Copyright (C) 2020-2024 Orsiris de Jong"
__licence__ = "BSD 3 Clause"
__version__ = "1.2.3"
__build__ = "2024101801"

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
# Try to import as absolute when used as module, import as relative for autotests
try:
    from cryptidy.hf_handling import add_hf, remove_hf
except ImportError:
    from .hf_handling import add_hf, remove_hf
# Python 2.7 compat fixes (missing typing and FileNotFoundError)
try:
    from typing import Any, Tuple, Union
except ImportError:
    pass

logger = getLogger()


def generate_keys(length=2048):
    # type: (int) -> Tuple[str, str]
    """
    RSA key pair generator

    :param length: key size, can be 1024, 2048 or 4096 bits
    :return: (tuple) private_key, public_key as PEM format
    """
    if length < 1024:
        raise ValueError("RSA key length must be >= 1024")
    private_key = RSA.generate(length)
    public_key = private_key.publickey()
    return private_key.export_key().decode(), public_key.export_key().decode()


def verify_key(key, key_type):
    # type: (str, str) -> None
    """
    Simple key type verification to make decryption debugging easier
    """
    if key is None:
        raise TypeError("No {} key provided.".format(key_type))

    # Python 2 fix where RSA keys are 'unicode' type, which does not exist in Python 3 anymore
    # Python 2 has a class 'basestring' which includes all string types
    if sys.version_info[0] < 3:
        # pylint: disable=E0602,undefined-variable
        string_type = basestring  # noqa: F821
    else:
        string_type = str
    if not isinstance(key, string_type):
        raise TypeError(
            "Wrong {} key provided. PEM encoded key should be passed, not bytes.".format(
                key_type
            )
        )
    if "-----BEGIN {} KEY-----\n".format(key_type) not in key:
        raise TypeError(
            "Wrong {} key provided. Does not look like a PEM encoded key.".format(
                key_type
            )
        )


def encrypt_message_hf(
    msg, key, header=b"", footer=b"", random_header_len=0, random_footer_len=0
):
    # type: (Any, str, Union[str, bytes], Union[str, bytes], int, int) -> bytes
    """
    Optional (user called fn) add headers / footers after encrypting
    """
    return add_hf(
        msg, key, encrypt_message, header, footer, random_header_len, random_footer_len
    )


def encrypt_message(msg, public_key):
    # type: (Any, str) -> bytes
    """
    Simple base64 wrapper for rsa_encrypt_message

    :param msg: original encrypted message
    :param public_key: rsa public key
    :return: (bytes) base64 encoded aes encrypted message
    """
    verify_key(public_key, "PUBLIC")
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

    try:
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
    except Exception as exc:  # pylint: disable=W0703,broad-except
        # goodenough(TM) Magic to avoid SyntaxError on PEP-0409 statements in Python < 3.3
        err = 'raise ValueError("Cannot RSA encrypt data: {}")'.format(exc)
        if sys.version_info[0] < 3 or (
            sys.version_info[0] == 3 and sys.version_info[1] < 4
        ):
            exec(err)
        else:
            exec(err + " from None")


def decrypt_message_hf(
    msg, key, header=None, footer=None, random_header_len=0, random_footer_len=0
):
    # type: (Union[bytes, str], str, Union[str, bytes], Union[str, bytes], int, int) -> Tuple[datetime, Any]
    """
    Optional (user called fn) remove headers / footers before decrypting
    """
    return remove_hf(
        msg, key, decrypt_message, header, footer, random_header_len, random_footer_len
    )


def decrypt_message(msg, private_key):
    # type: (Union[bytes, str], str) -> Tuple[datetime, Any]
    """
    Simple base64 wrapper for rsa_decrypt_message

    :param msg: b64 encoded original rsa encrypted data
    :param private_key: rsa private key
    :return: (bytes): rsa decrypted data
    """
    verify_key(private_key, "RSA PRIVATE")
    try:
        decoded_msg = b64decode(msg)
    except (TypeError, binascii_Error):
        raise TypeError(
            "decrypt_message accepts b64 encoded byte objects"
        )  # pylint: disable=W0707,raise-missing-from

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
    private_key = None  # Wipe from memory as soon as possible
    enc_session_key, aes_encrypted_msg = (
        msg[0:enc_session_key_size],
        msg[enc_session_key_size:],
    )
    try:
        session_key = cipher_rsa.decrypt(enc_session_key)
    except TypeError:
        raise TypeError(
            "You need a private key to decrypt data."
        )  # pylint: disable=W0707,raise-missing-from
    except ValueError as exc:
        # goodenough(TM) Magic to avoid SyntaxError on PEP-0409 statements in Python < 3.3
        err = 'raise ValueError("RSA Integrity check failed, cannot decrypt data: {}")'.format(
            exc
        )
        if sys.version_info[0] < 3 or (
            sys.version_info[0] == 3 and sys.version_info[1] < 4
        ):
            exec(err)
        else:
            exec(err + " from None")

    return aes_decrypt_message(aes_encrypted_msg, session_key)
