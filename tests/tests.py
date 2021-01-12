#! /usr/bin/env python
#  -*- coding: utf-8 -*-
#
# This file is part of cryptidy module

"""
The cryptidy module wraps PyCrpytodome(x) functions into simple
symmetric and asymmetric functions


Versioning semantics:
    Major version: backward compatibility breaking changes
    Minor version: New functionality
    Patch version: Backwards compatible bug fixes

"""

__intname__ = 'cryptidy_tests'
__author__ = 'Orsiris de Jong'
__copyright__ = 'Copyright (C) 2018-2021 Orsiris de Jong'
__licence__ = 'BSD 3 Clause'
__version__ = '1.0.1'
__build__ = '2021011101'

from cryptidy import padding
from cryptidy import aes_encryption
from cryptidy import symmetric_encryption
from cryptidy import asymmetric_encryption


def test_pad_selftest():
    print('Example code for %s, %s' % (__intname__, __build__))
    from datetime import datetime
    msg = '%s' % datetime.now()
    padded_msg = padding.pad(msg)
    unpadded_msg = padding.unpad(padded_msg)
    print('Original timestamp: %s' % msg)
    print('Padded timestamp: %s' % padded_msg)
    print('Unpadded timestamp: %s' % unpadded_msg)

    assert len(padded_msg) == 32, 'Padded message is not 32 chars long.'
    assert msg == unpadded_msg, 'Original message and unpadded one should be the same.'


def test_aes_selftest():
    """
    Self test function
    """
    print('Example code for %s, %s' % (__intname__, __build__))
    print('Example key generation and data encryption using AES-256-EAX')
    for key_size in [16, 32]:
        key = aes_encryption.generate_key(key_size)
        print('Key is %s' % key_size)

        assert len(key) == key_size, 'Encryption key should be 32 bytes long.'

        msg = b'This is a meessage'
        print('Original message: {0}'.format(msg))
        enc_msg = aes_encryption.aes_encrypt(msg, key)
        print('Encoded message: {0}'.format(enc_msg))
        dec_msg = aes_encryption.aes_decrypt(key, *enc_msg)
        print('Decoded message: {0}'.format(dec_msg))

        assert msg == dec_msg, 'Original message and decrypted one should be the same.'


def test_sym_selftest():
    """
    Self test function
    """
    print('Example code for %s, %s' % (__intname__, __build__))
    print('Example key generation and data encryption using AES-256-EAX')
    for key_size in [16, 32]:
        key = symmetric_encryption.generate_key(key_size)
        print('\nKey is %s bytes long\n' % key_size)

        assert len(key) == key_size, 'Encryption key should be 16 or 32 bytes long.'

        msg = ['This list shall be encrypted', 'This string in list will be encrypted']
        print(msg)
        enc_msg = symmetric_encryption.encrypt_message(msg, key)
        print('Encrypted message: %s ' % enc_msg)
        timestamp, dec_msg = symmetric_encryption.decrypt_message(enc_msg, key)
        print('Decrypted message: date=%s: %s ' % (timestamp, dec_msg))

        assert msg == dec_msg, 'Original message and decrypted one should be the same.'

        test_list = ['This list', 'will be', 'encrypted too !']
        print(test_list)
        enc_list = symmetric_encryption.encrypt_message(test_list, key)
        print('Encrypted list: %s ' % enc_list)
        timestamp, dec_list = symmetric_encryption.decrypt_message(enc_list, key)
        print('Decrypted list: date=%s: %s ' % (timestamp, dec_list))

        assert test_list == dec_list, 'Original list and decrypted one should be the same.'

        # We shall also check for multiline strings that shall be encrypted / decrypted as one
        test_mlstring = "Hello\nWorld"
        print(test_mlstring)
        enc_mlstring = symmetric_encryption.encrypt_message(test_mlstring, key)
        print('Encrypted multiline string: %s ' % enc_mlstring)
        timestap, dec_mlstring = symmetric_encryption.decrypt_message(enc_mlstring, key)
        print('Decrypted multiline string: date=%s: %s ' % (timestamp, dec_mlstring))

        assert test_mlstring == dec_mlstring, 'Original multiline string and decrypted one should be the same.'


def test_asym_selftest():
    """
    Self test function
    """
    print('Example code for %s, %s' % (__intname__, __build__))
    print('Example RSA private and public key generation and data encryption using AES-256-EAX')
    for key_size in [1024, 2048, 4096]:
        print('\nTesting with %s bits RSA key.\n' % key_size)
        priv_key, pub_key = asymmetric_encryption.generate_keys(key_size)

        assert '-----END RSA PRIVATE KEY-----' in priv_key, 'Bogus privkey generated.'
        assert '-----END PUBLIC KEY-----' in pub_key, 'Bogus pubkey generated.'

        msg = b'This string will be encrypted'
        enc_msg = asymmetric_encryption.encrypt_message(msg, pub_key)
        print('Encrypted message: %s ' % enc_msg)
        timestamp, dec_msg = asymmetric_encryption.decrypt_message(enc_msg, priv_key)
        print('Decrypted message from %s: %s ' % (timestamp, dec_msg))

        assert msg == dec_msg, 'Original message and decrypted one should be the same.'

        test_list = ['This list', 'will be', 'encrypted too !']
        enc_test_list = asymmetric_encryption.encrypt_message(test_list, pub_key)
        print('Encrypted list: %s ' % enc_test_list)
        timestamp, dec_test_list = asymmetric_encryption.decrypt_message(enc_test_list, priv_key)
        print('Decrypted message from %s: %s ' % (timestamp, dec_test_list))

        assert test_list == dec_test_list, 'Original list and decrypted one should be the same.'

        # Make a "double pickle" test since symmetric encryption already pickles the message
        import pickle
        data = pickle.dumps(('a', 'b', 'c'))
        enc_data = asymmetric_encryption.encrypt_message(data, pub_key)
        print('Encrypted data: %s ' % enc_data)
        timestamp, dec_data = asymmetric_encryption.decrypt_message(enc_data, priv_key)
        print('Decrypted message from %s: %s ' % (timestamp, pickle.loads(dec_data)))

        assert data == dec_data, 'Original data and decrypted one should be the same.'

        print('Test done with %s bits RSA key.' % key_size)
