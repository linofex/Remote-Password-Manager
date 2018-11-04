#! /usr/bin/env python
#  -*- coding: utf-8 -*-
#  Author: Fabio Condomitti
#    Jun 11, 2018 12:54:15 PM

import os
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend

global init
init = False

def kdf(password):

    backend = default_backend()

    with open('salt.txt', 'r') as fp:
        salt = fp.readlines()

    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=bytes(salt),
        iterations=100000,
        backend=backend
    )
    key = kdf.derive(bytes(password))
    
    """# verify
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=backend
    )
    if kdf.verify(b"my great password", key) is True:
        return key"""
    
    return key