# cryptidy
## Python high level library for symmetric & asymmetric encryption

[![License](https://img.shields.io/badge/License-BSD%203--Clause-blue.svg)](https://opensource.org/licenses/BSD-3-Clause)
[![Percentage of issues still open](http://isitmaintained.com/badge/open/netinvent/cryptidy.svg)](http://isitmaintained.com/project/netinvent/Cryptidy "Percentage of issues still open")
[![Maintainability](https://api.codeclimate.com/v1/badges/be5d6edea1288951dc07/maintainability)](https://codeclimate.com/github/netinvent/cryptidy/maintainability)
[![codecov](https://codecov.io/gh/netinvent/cryptidy/branch/master/graph/badge.svg?token=E5D9oVnqj7)](https://codecov.io/gh/netinvent/cryptidy)
[![linux-tests](https://github.com/netinvent/cryptidy/actions/workflows/linux.yaml/badge.svg)](https://github.com/netinvent/cryptidy/actions/workflows/linux.yaml)
[![windows-tests](https://github.com/netinvent/cryptidy/actions/workflows/windows.yaml/badge.svg)](https://github.com/netinvent/cryptidy/actions/workflows/windows.yaml)
[![GitHub Release](https://img.shields.io/github/release/netinvent/cryptidy.svg?label=Latest)](https://github.com/netinvent/cryptidy/releases/latest)

This library has been written to make encryption / decryption of any python object as simple as possible.
It is based on AES encryption (265 or 128 bytes).

It's main features are:
 - Encrypt any pickable Python object / variables
 - Add an UTC timestamp to the encrypted message
 - Verify that decrypted messages timestamps aren't in the future
 - Allow symmetric encryption (AES)
     - 128, 192 or 256 bits encryption
 - Allow asymmetric encryption (RSA + AES)
     - 1024, 2048 or 4096 bits encryption using AES128 (1024 bits RSA) or AES256 (2048 or 4096 bits RSA)
 - Provide the encypted data as base64 string for maximum portability between platforms and encodings
 - Unload AES key from memory as soon as possible to help prevent memory attacks

# Setup

cryptidy requires Python 2.7+

`pip install cryptidy`


# Symmetric encryption usage

```
from cryptidy import symmetric_encryption

key = symmetric_encryption.generate_key(32)  # 32 bytes = 256 bits

some_python_object = ['foo', 'bar']
encrypted = symmetric_encryption.encrypt_message(some_python_object, key)
timestamp, original_object = symmetric_encryption.decrypt_message(encrypted, key)
```

# Asymmetric encryption usage

```
from cryptidy import asymmetric_encryption

priv_key, pub_key = asymmetric_encryption.generate_keys(2048)  # 2048 bits RSA key
some_python_object = ['foo', 'bar']
encrypted = asymmetric_encryption.encrypt_message(some_python_object, pub_key)
timestamp, original_object = asymmetric_encryption.decrypt_message(encrypted, priv_key)
```
