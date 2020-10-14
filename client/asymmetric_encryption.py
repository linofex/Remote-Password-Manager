#! /usr/bin/env python
#  -*- coding: utf-8 -*-
#  Author: Fabio Condomitti
#    Jun 11, 2018 12:54:15 PM

import binascii
import os

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat      
from cryptography.exceptions import AlreadyFinalized
from cryptography.hazmat.primitives.asymmetric import padding as paddingAsymm
from cryptography.hazmat.primitives import serialization

def createCiphertextRSA(serverPublicKey, plaintext):
    ciphertext = serverPublicKey.encrypt(
        bytes(plaintext),
        paddingAsymm.OAEP(
            mgf=paddingAsymm.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    return ciphertext

def publicKeyLoading():
    path = os.path.join('Asymmetric_Criptography', 'rsa_pubkey.pem')
    #path = './Asymmetric_Criptography/rsa_pubkey.pem'
    
    with open(path, "rb") as key_file:
        public_key = serialization.load_pem_public_key(
        key_file.read(),
        backend=default_backend()
        )

    return public_key

def privateKeyLoading():
    path = os.path.join('Asymmetric_Criptography', 'rsa_prvkey.pem')
    #path = './Asymmetric_Criptography/rsa_pubkey.pem'
    
    with open(path, "rb") as key_file:
        private_key = serialization.load_pem_private_key(
            key_file.read(),
            password=None,
            backend=default_backend()
        )
    
    return private_key

def encryptPassword(password):
    
    public_key = publicKeyLoading()
    path = os.path.join('Asymmetric_Criptography', 'rsa_prvkey.pem')

    ciphertext = public_key.encrypt(
        password,
        paddingAsymm.OAEP(
            mgf=paddingAsymm.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    return ciphertext

def decryptPassword(ciphertext):
    private_key = privateKeyLoading()

    plaintext = private_key.decrypt(
        ciphertext,
        paddingAsymm.OAEP(
            mgf=paddingAsymm.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return plaintext
