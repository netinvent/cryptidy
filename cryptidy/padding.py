#! /usr/bin/env python
#  -*- coding: utf-8 -*-
#
# This file is part of cryptidy module

"""
Padding functions for cryptography usage

Versioning semantics:
    Major version: backward compatibility breaking changes
    Minor version: New functionality
    Patch version: Backwards compatible bug fixes

"""

__intname__ = "cryptidy.padding"
__author__ = "Orsiris de Jong"
__copyright__ = "Copyright (C) 2018-2024 Orsiris de Jong"
__licence__ = "BSD 3 Clause"
__version__ = "0.1.2"
__build__ = "2021011101"


def pad(string, pad_len=32):
    # type: (str, int) -> str
    """
    Simple function that allows to lengthen a string to a defined length
    """
    return string + (pad_len - len(string) % pad_len) * chr(
        pad_len - len(string) % pad_len
    )


def unpad(string):
    # type: (str) -> str
    """
    Simple function that exctracts the initial string from a padded string
    """
    return string[0 : -ord(string[-1])]


# lambda function version
# pad_len = 32
# pad = (lambda s: s + (pad_len - len(s) % pad_len) * chr(pad_len - len(s) % pad_len))
# unpad = lambda s: s[0:-ord(s[-1])]
