#! /usr/bin/env python
#  -*- coding: utf-8 -*-
#
# This file is part of cryptidy module

"""
Add or remove headers / footers to byte messages

Versioning semantics:
    Major version: backward compatibility breaking changes
    Minor version: New functionality
    Patch version: Backwards compatible bug fixes

"""

__intname__ = "cryptidy.hf_handling"
__author__ = "Orsiris de Jong"
__copyright__ = "Copyright (C) 2018-2024 Orsiris de Jong"
__licence__ = "BSD 3 Clause"
__version__ = "1.2.1"
__build__ = "2024121001"


from datetime import datetime

# Python 2.7 compat fixes (missing typing and FileNotFoundError)
try:
    from typing import Any, Union, Callable, Tuple
except ImportError:
    pass
# noqaF401: generate_key is not used here, but should be available from the pacakge, disabling flake8 check
try:
    # pylint: disable=W0611,unused-import
    from cryptidy.aes_encryption import (
        generate_random_string,
    )  # noqa: F401
except ImportError:
    from .aes_encryption import (
        generate_random_string,
    )  # noqa: F401


def add_hf(
    msg,
    key,
    encrypt_fn,
    header=b"",
    footer=b"",
    random_header_len=0,
    random_footer_len=0,
):
    # type: (Any, str, Callable, Union[str, bytes], Union[str, bytes], int, int) -> bytes
    """
    Simple wrapper for encrypt_message that adds  a given (or random) header and footer
    This function solely exists for compat reasons
    When a header/footer is added, it serves for message identification (eg like rsa key header/footers)
    When random bytes are requested, it serves to additional scramble data
    """
    if header and isinstance(header, str):
        header = header.encode("utf-8")
    if random_header_len > 0:
        header += generate_random_string(random_header_len).encode("utf-8")
    if footer and isinstance(footer, str):
        footer = footer.encode("utf-8")
    if random_footer_len > 0:
        footer += generate_random_string(random_footer_len).encode("utf-8")
    return header + encrypt_fn(msg, key) + footer


def remove_hf(
    msg,
    key,
    decrypt_fn,
    header=None,
    footer=None,
    random_header_len=0,
    random_footer_len=0,
):
    # type: (Union[bytes, str], str, Callable, Union[str, bytes], Union[str, bytes], int, int) -> Tuple[datetime, Any]
    """
    Simple wrapper for decrypt_message that adds random header and footer chars
    This function solely exists for compat reasons
    """
    # Remove header and footer if set
    if header:
        msg = msg[len(header) :]
    if footer:
        msg = msg[: -len(footer)]

    if random_footer_len > 0:
        return decrypt_fn(msg[random_header_len:][:-random_footer_len], key)
    return decrypt_fn(msg[random_header_len:], key)
