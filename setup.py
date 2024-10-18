#! /usr/bin/env python
#  -*- coding: utf-8 -*-
#
# This file is part of cryptidy package


__intname__ = "cryptidy.setup"
__author__ = "Orsiris de Jong"
__copyright__ = "Copyright (C) 2021 Orsiris de Jong"
__licence__ = "BSD 3 Clause"
__build__ = "2021031601"

import os
import sys

import pkg_resources
import setuptools


def _read_file(filename):
    here = os.path.abspath(os.path.dirname(__file__))
    if sys.version_info[0] > 2:
        with open(os.path.join(here, filename), "r", encoding="utf-8") as file_handle:
            return file_handle.read()
    else:
        # With python 2.7, open has no encoding parameter, resulting in TypeError
        # Fix with io.open (slow but works)
        from io import open as io_open

        with io_open(
            os.path.join(here, filename), "r", encoding="utf-8"
        ) as file_handle:
            return file_handle.read()


def get_metadata(package_file):
    """
    Read metadata from package file
    """

    _metadata = {}

    for line in _read_file(package_file).splitlines():
        if line.startswith("__version__") or line.startswith("__description__"):
            delim = "="
            _metadata[line.split(delim)[0].strip().strip("__")] = (
                line.split(delim)[1].strip().strip("'\"")
            )
    return _metadata


def parse_requirements(filename):
    """
    There is a parse_requirements function in pip but it keeps changing import path
    Let's build a simple one
    """
    try:
        requirements_txt = _read_file(filename)
        install_requires = [
            str(requirement)
            for requirement in pkg_resources.parse_requirements(requirements_txt)
        ]
        return install_requires
    except OSError:
        print(
            'WARNING: No requirements.txt file found as "{}". Please check path or create an empty one'.format(
                filename
            )
        )


PACKAGE_NAME = "cryptidy"
package_path = os.path.abspath(PACKAGE_NAME)
package_file = os.path.join(package_path, "__init__.py")
metadata = get_metadata(package_file)
requirements = parse_requirements(os.path.join(package_path, "requirements.txt"))
long_description = _read_file("README.md")

setuptools.setup(
    name=PACKAGE_NAME,
    packages=setuptools.find_packages(),
    version=metadata["version"],
    install_requires=requirements,
    description=metadata["description"],
    license="BSD",
    author="NetInvent - Orsiris de Jong",
    author_email="contact@netinvent.fr",
    url="https://github.com/netinvent/cryptidy",
    keywords=[
        "cryptography",
        "symmetric",
        "asymmetric",
        "high",
        "level",
        "api",
        "easy",
    ],
    long_description=long_description,
    long_description_content_type="text/markdown",
    pyton_requires=">=2.7",
    classifiers=[
        "Development Status :: 5 - Production/Stable",
        "Intended Audience :: Developers",
        "Topic :: Software Development",
        "Topic :: System",
        "Topic :: System :: Operating System",
        "Topic :: System :: Shells",
        "Programming Language :: Python",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: Implementation :: CPython",
        "Programming Language :: Python :: Implementation :: PyPy",
        "Operating System :: POSIX :: Linux",
        "Operating System :: POSIX :: BSD :: FreeBSD",
        "Operating System :: POSIX :: BSD :: NetBSD",
        "Operating System :: POSIX :: BSD :: OpenBSD",
        "Operating System :: Microsoft",
        "Operating System :: Microsoft :: Windows",
        "License :: OSI Approved :: BSD License",
    ],
)
