#! /usr/bin/env python

from setuptools import setup

setup(
    name = 'pwnvasive',
    version = '0.1',
    packages=['pwnvasive'],
    scripts = [ 'bin/pwnvasive' ],

    # Metadata
    author = 'Philippe BIONDI',
    author_email = 'phil@secdev.org',
    description = 'Semi-automatic discovery and lateralization tool',
    install_requires = [
        "asyncssh",
        "aiocmd",
        "graphviz",
        "bcrypt",
        "aiohttp",
    ],
    license = 'GPLv2',
    # keywords = '',

)
