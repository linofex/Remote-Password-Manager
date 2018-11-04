#! /usr/bin/env python
#  -*- coding: utf-8 -*-
#  Author: Fabio Condomitti
#    Jun 11, 2018 12:54:15 PM

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher
from cryptography.hazmat.primitives.ciphers import modes
from cryptography.hazmat.primitives.ciphers import algorithms
from cryptography.hazmat.primitives import padding as paddingSymm
from cryptography.exceptions import AlreadyFinalized

def createPlaintextAES(kcs, iv, cryptogram):

    cipher = Cipher(algorithms.AES(kcs), modes.CBC(iv), default_backend())
    ctx = cipher.decryptor()
    padded_plaintext = ctx.update(cryptogram) + ctx.finalize()

    block = algorithms.AES.block_size/8
    ctx = paddingSymm.PKCS7(8*block).unpadder()
    plaintext = ctx.update(padded_plaintext) + ctx.finalize()

    return plaintext

def encrypt_AES(msg, key, IV):
    
    padder = paddingSymm.PKCS7(128).padder()
    padded_data = padder.update(bytes(msg))
    padded_data += padder.finalize()

    if len(key) is not 32 or len(IV) is not 16:
        print key, IV
        print len(key), len(IV)
        print '[ERROR] Wrong length'
        return None

    backend = default_backend()
    cipher = Cipher(algorithms.AES(key), modes.CBC(IV), backend=backend)
    try:
        encryptor = cipher.encryptor()
        ct = encryptor.update(padded_data) + encryptor.finalize()
        return ct
    except:
        print "Encryption"
        return None

def decrypt_AES(encrypted_data, key, IV):

    if len(key) is not 32 or len(IV) is not 16:
        #print key, IV
        print IV
        print len(key), len(IV)
        print '[ERROR] Wrong length'
        return None
        
    cipher = Cipher(algorithms.AES(key), modes.CBC(IV), default_backend())
    
    try:

        ctx = cipher.decryptor()
        padded_plaintext = ctx.update(encrypted_data) + ctx.finalize()
        ctx = paddingSymm.PKCS7(128).unpadder()
        plaintext = ctx.update(padded_plaintext) + ctx.finalize()
        
        return plaintext
    
    except AlreadyFinalized:
        print "[ERROR] AlreadyFinalized Exception"
        return None